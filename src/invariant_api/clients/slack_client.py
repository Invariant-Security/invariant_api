"""Notificação best-effort pro Slack quando um lead novo é cadastrado --
NUNCA a fonte de verdade (ver routes/leads.py: persiste no Postgres
primeiro, sempre). Webhook lido no ponto de uso (não em constante
module-level), mesma convenção de MERCADO_PAGO_ACCESS_TOKEN em
billing.py -- nunca exposto ao frontend, nunca commitado, nunca logado.

Payload em Block Kit com `plain_text`: Slack não interpreta `<!channel>`/
`<@id>`/link markup dentro de plain_text, então nenhum dado fornecido
pelo visitante (nome, empresa, cargo, mensagem) consegue virar menção ou
formatação especial. O campo `text` de fallback (preview de notificação)
fica sempre estático, sem dado do usuário.
"""

import os
import time

import httpx

_MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = [0.3, 0.8]  # entre a 1ª/2ª e a 2ª/3ª tentativa

_SCOPE_LABELS = {"linux": "Linux", "containers": "Containers", "linux_containers": "Linux + Containers"}
_SIZE_LABELS = {
    "1_10": "1–10",
    "11_50": "11–50",
    "51_100": "51–100",
    "100_plus": "Mais de 100",
    "evaluating": "Ainda avaliando",
}
_NEED_LABELS = {
    "compliance_cis": "Conformidade / CIS",
    "audit": "Auditoria",
    "evidence": "Evidências",
    "hardening": "Hardening",
    "devsecops": "DevSecOps",
    "other": "Outro",
}


def _build_payload(
    *,
    name: str,
    email: str,
    company: str,
    role: str | None,
    target_scope: str,
    environment_size: str | None,
    primary_need: str | None,
    message: str | None,
) -> dict:
    lines = [
        f"Nome: {name}",
        f"Empresa: {company}",
        f"Cargo: {role or '-'}",
        f"E-mail: {email}",
        "",
        f"Interesse: {_SCOPE_LABELS.get(target_scope, target_scope)}",
        f"Ambientes: {_SIZE_LABELS.get(environment_size, environment_size) if environment_size else '-'}",
        f"Necessidade: {_NEED_LABELS.get(primary_need, primary_need) if primary_need else '-'}",
        "",
        "Mensagem:",
        message or "-",
        "",
        "Origem: invariantsec.org",
    ]
    return {
        # Preview de notificação -- sempre estático, sem dado do usuário.
        "text": "🚀 Novo lead pelo site",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "🚀 Novo lead pelo site"}},
            # plain_text: Slack nunca interpreta <!channel>/<@id>/markup
            # aqui, mesmo que o visitante tente injetar isso em qualquer
            # campo do formulário.
            {"type": "section", "text": {"type": "plain_text", "text": "\n".join(lines)[:2900]}},
        ],
    }


def notify_lead(
    *,
    name: str,
    email: str,
    company: str,
    role: str | None,
    target_scope: str,
    environment_size: str | None,
    primary_need: str | None,
    message: str | None,
) -> tuple[bool, int, str | None]:
    """(sent, attempts, last_error). sent=True só se uma tentativa real
    teve sucesso. Sem webhook configurado: (False, 0, None) -- não é
    falha, só não há canal ainda. last_error é sempre um código curto e
    estável (nunca a exceção crua nem a URL do webhook).
    """
    webhook_url = os.environ.get("SLACK_LEADS_WEBHOOK_URL")
    if not webhook_url:
        return False, 0, None

    payload = _build_payload(
        name=name,
        email=email,
        company=company,
        role=role,
        target_scope=target_scope,
        environment_size=environment_size,
        primary_need=primary_need,
        message=message,
    )
    last_error = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = httpx.post(webhook_url, json=payload, timeout=5)
            resp.raise_for_status()
            return True, attempt, None
        except httpx.TimeoutException:
            last_error = "timeout"
        except httpx.HTTPStatusError as e:
            last_error = f"http_{e.response.status_code}"
        except Exception:
            last_error = "error"
        if attempt < _MAX_ATTEMPTS:
            time.sleep(_BACKOFF_SECONDS[attempt - 1])
    return False, _MAX_ATTEMPTS, last_error
