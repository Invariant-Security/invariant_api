"""Captura de lead comercial (formulário "Fale com a Invariant" da home
-- sem fluxo de pagamento nenhum, só follow-up manual do time comercial).
Persistência no Postgres é a fonte de verdade; a notificação do Slack
roda em BackgroundTasks depois da resposta já ter saído -- melhor
esforço, nunca bloqueia o visitante nem vira erro se falhar.
"""

import logging
import re
import time
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, field_validator

from invariant_api.clients import slack_client
from invariant_api.storage import postgres as db

router = APIRouter()
logger = logging.getLogger(__name__)

MAX_NAME_LENGTH = 200
MAX_EMAIL_LENGTH = 254  # limite prático de RFC 5321
MAX_COMPANY_LENGTH = 200
MAX_ROLE_LENGTH = 200
MAX_MESSAGE_LENGTH = 2000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Limitação em memória, de propósito, documentada: reinício do processo
# limpa o estado, múltiplos workers/réplicas teriam contadores
# independentes (não é o caso hoje -- um processo `api` só nesta stack).
# Suficiente como proteção básica sem Redis nesta rodada. Purge simples
# evita crescimento ilimitado (IP que nunca mais volta não fica pra
# sempre no dict): remove a própria entrada quando fica vazia, e faz uma
# varredura completa só quando o mapa cresce além do teto -- não é um
# job/scheduler dedicado, só uma checagem barata dentro da própria
# chamada que já está acontecendo.
_RATE_LIMIT_WINDOW_SECONDS = 600
_RATE_LIMIT_MAX_REQUESTS = 5
_RATE_LIMIT_MAX_TRACKED_IPS = 10_000
_rate_limit_state: dict[str, list[float]] = {}


def _check_rate_limit(ip: str) -> None:
    now = time.time()
    recent = [t for t in _rate_limit_state.get(ip, []) if now - t < _RATE_LIMIT_WINDOW_SECONDS]
    if not recent:
        _rate_limit_state.pop(ip, None)
    if len(recent) >= _RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(429, "Muitas tentativas. Tente novamente mais tarde.")
    recent.append(now)
    _rate_limit_state[ip] = recent

    if len(_rate_limit_state) > _RATE_LIMIT_MAX_TRACKED_IPS:
        for other_ip in list(_rate_limit_state):
            other_recent = [t for t in _rate_limit_state[other_ip] if now - t < _RATE_LIMIT_WINDOW_SECONDS]
            if other_recent:
                _rate_limit_state[other_ip] = other_recent
            else:
                del _rate_limit_state[other_ip]


class LeadRequest(BaseModel):
    name: str
    email: str
    company: str
    role: str | None = None
    target_scope: Literal["linux", "containers", "linux_containers"]
    environment_size: Literal["1_10", "11_50", "51_100", "100_plus", "evaluating"] | None = None
    primary_need: Literal["compliance_cis", "audit", "evidence", "hardening", "devsecops", "other"] | None = None
    message: str | None = None
    # Honeypot -- campo escondido no frontend (fora da tela, aria-hidden).
    # Humano nunca preenche; bot que preenche formulário "às cegas" cai
    # aqui na maioria das vezes.
    website: str = ""

    @field_validator("name", "email", "company", "role", "message", mode="before")
    @classmethod
    def _trim(cls, v):
        return v.strip() if isinstance(v, str) else v


class LeadResponse(BaseModel):
    status: str


def _validate_lengths(payload: LeadRequest) -> None:
    if len(payload.name) > MAX_NAME_LENGTH:
        raise HTTPException(422, f"Nome excede o limite de {MAX_NAME_LENGTH} caracteres.")
    if len(payload.email) > MAX_EMAIL_LENGTH:
        raise HTTPException(422, f"E-mail excede o limite de {MAX_EMAIL_LENGTH} caracteres.")
    if len(payload.company) > MAX_COMPANY_LENGTH:
        raise HTTPException(422, f"Empresa excede o limite de {MAX_COMPANY_LENGTH} caracteres.")
    if payload.role and len(payload.role) > MAX_ROLE_LENGTH:
        raise HTTPException(422, f"Cargo excede o limite de {MAX_ROLE_LENGTH} caracteres.")
    if payload.message and len(payload.message) > MAX_MESSAGE_LENGTH:
        raise HTTPException(422, f"Mensagem excede o limite de {MAX_MESSAGE_LENGTH} caracteres.")


def _notify_slack_and_record(*, lead_id: int, payload: LeadRequest) -> None:
    """Roda em background (ver BackgroundTasks abaixo) -- conexão própria,
    não reaproveita a do request original (que já foi fechada antes da
    resposta sair). TODA a chamada ao Slack fica dentro do try -- um erro
    inesperado montando o payload ou no client (não só uma falha HTTP já
    tratada dentro de notify_lead) nunca desaparece em silêncio.
    """
    sent, attempts, last_error = False, 0, None
    try:
        sent, attempts, last_error = slack_client.notify_lead(
            name=payload.name,
            email=payload.email,
            company=payload.company,
            role=payload.role,
            target_scope=payload.target_scope,
            environment_size=payload.environment_size,
            primary_need=payload.primary_need,
            message=payload.message,
        )
    except Exception:
        logger.exception("Erro inesperado notificando Slack pro lead %s", lead_id)
        last_error = "error"  # nunca a exceção crua

    try:
        with db.connect() as conn:
            db.update_lead_slack_result(conn, id=lead_id, notified=sent, attempts=attempts, last_error=last_error)
            conn.commit()
        if not sent and (attempts > 0 or last_error):
            logger.warning("Slack não confirmou o lead %s (tentativas=%s): %s", lead_id, attempts, last_error)
    except Exception:
        logger.exception("Falha ao registrar resultado do Slack pro lead %s", lead_id)


@router.post("/leads", response_model=LeadResponse)
def create_lead(payload: LeadRequest, request: Request, background_tasks: BackgroundTasks) -> LeadResponse:
    if payload.website:
        logger.info("lead honeypot preenchido, ignorado silenciosamente")
        return LeadResponse(status="received")  # finge sucesso, não persiste, não notifica

    # X-Real-IP: setado pelo NOSSO nginx-proxy a partir do CF-Connecting-IP
    # do Cloudflare -- `api` nunca expõe porta de host (só `expose`, sem
    # `ports`), então um atacante na internet pública não alcança `api`
    # direto pra forjar esse header. MAS `vps-proxy` é uma rede docker
    # compartilhada por TODOS os projetos desta VPS (confirmado via
    # `docker network inspect vps-proxy` -- outros containers de outros
    # projetos estão nela) -- outro container já presente nessa rede
    # tecnicamente poderia chamar essa rota direto e forjar X-Real-IP,
    # contornando o rate limit. Aceito como limitação conhecida (exigiria
    # já controlar outro container desta VPS -- fora do modelo de ameaça
    # de "visitante público abusando do formulário"), não uma garantia
    # perfeita contra ameaça interna.
    client_ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
    _check_rate_limit(client_ip)

    if not payload.name or not payload.company:
        raise HTTPException(422, "Nome e empresa são obrigatórios.")
    if not _EMAIL_RE.match(payload.email):
        raise HTTPException(422, "E-mail inválido.")
    _validate_lengths(payload)

    with db.connect() as conn:
        lead_id = db.insert_lead(
            conn,
            name=payload.name,
            email=payload.email,
            company=payload.company,
            role=payload.role,
            target_scope=payload.target_scope,
            environment_size=payload.environment_size,
            primary_need=payload.primary_need,
            message=payload.message,
        )
        conn.commit()

    background_tasks.add_task(_notify_slack_and_record, lead_id=lead_id, payload=payload)
    return LeadResponse(status="received")
