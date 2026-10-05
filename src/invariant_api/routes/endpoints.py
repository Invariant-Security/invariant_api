"""CRUD de endpoints (IP individual ou CIDR) + gatilho de discovery.
Guardado por require_admin_session -- mesma proteção de routes/assess.py,
routes/reports.py e routes/ingest.py (ver seus próprios comentários).
/api/demo/* continua sem auth, de propósito: só lê arquivo estático
gravado por demo.sh, nunca Docker/SSH ao vivo.

Escopo desta etapa: só identificar o tipo de cada endpoint (Windows/Linux/
Docker/WAF/firewall/VMware) e devolver a classificação. Rodar checks CIS
de verdade contra o que foi descoberto aqui é etapa futura (ver
invariant_assessment/preocupacoes.md pro gap de transporte que isso
plugaria).
"""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

import httpx
import psycopg
from fastapi import APIRouter, Depends, Header, HTTPException, Response
from invariant_contracts import DiscoveryResult, Endpoint, Finding, v1
from pydantic import BaseModel, Field

from invariant_api import assessment_runs
from invariant_api.auth import require_admin_session
from invariant_api.clients import assessment_client, discovery_client
from invariant_api.demo_sanitize import is_demo_endpoint
from invariant_api.routes.assess import _findings_from_run
from invariant_api.storage import postgres as db

router = APIRouter(prefix="/endpoints", dependencies=[Depends(require_admin_session)])

logger = logging.getLogger(__name__)

# Mesmo valor de demo_host_snapshot.py's _NO_STORE_HEADERS -- constante
# local de propósito (nome privado de outro módulo de rota não é
# importado entre eles), só pra GET /endpoints (ver seu próprio
# docstring).
_NO_STORE_HEADERS = {"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"}

# Teto simples pra evitar um arquivo gigante virando milhares de inserts
# numa chamada só -- também barra abuso acidental na demo. O tamanho do
# arquivo em si já é limitado no frontend antes do upload; isso aqui é o
# teto de itens, reforçado no lado que efetivamente escreve no banco.
MAX_BULK_ENDPOINTS = 500


def _validate_address(address: str) -> None:
    try:
        ipaddress.ip_network(address, strict=False)
    except ValueError as e:
        raise HTTPException(422, f"{address!r} is not a valid IP or CIDR range: {e}") from e


@router.post("")
def create_endpoint(payload: Endpoint) -> dict:
    _validate_address(payload.address)
    conn = db.connect()
    endpoint_id = db.insert_endpoint(conn, address=payload.address, label=payload.label, tags=payload.tags)
    conn.commit()
    conn.close()
    return {"id": endpoint_id, "address": payload.address, "label": payload.label, "tags": payload.tags}


class BulkEndpointInput(BaseModel):
    """`row` é o número de linha real do arquivo de origem (CSV), calculado
    pelo frontend que é quem lê o arquivo -- nunca deduzido aqui pela
    posição no array, já que cabeçalho/linhas vazias/linhas ignoradas
    fazem a posição no array divergir da linha real do arquivo.
    """

    row: int
    address: str
    label: str | None = None
    tags: list[str] = []


class BulkEndpointResult(BaseModel):
    row: int
    address: str
    label: str | None = None
    status: Literal["created", "error"]
    id: int | None = None
    detail: str | None = None


# Declarada logo depois do POST "" (item único) e ANTES de qualquer rota
# dinâmica /{endpoint_id}/... de propósito -- se um dia existir uma rota
# POST /{endpoint_id} de verbo igual, o FastAPI/Starlette casa pela ordem
# de declaração, e "bulk" não pode nunca ser interpretado como um
# endpoint_id. Hoje não há conflito real (as únicas rotas dinâmicas POST
# são /{endpoint_id}/discover, /assess, /check, formato de path
# diferente), mas a ordem já fica correta por garantia.
@router.post("/bulk", response_model=list[BulkEndpointResult])
def create_endpoints_bulk(payload: list[BulkEndpointInput]) -> list[BulkEndpointResult]:
    if len(payload) > MAX_BULK_ENDPOINTS:
        raise HTTPException(422, f"Máximo de {MAX_BULK_ENDPOINTS} endpoints por importação.")
    results = []
    conn = db.connect()
    try:
        for item in payload:
            try:
                _validate_address(item.address)
                endpoint_id = db.insert_endpoint(conn, address=item.address, label=item.label, tags=item.tags)
                conn.commit()
                results.append(
                    BulkEndpointResult(
                        row=item.row, address=item.address, label=item.label, status="created", id=endpoint_id
                    )
                )
            except HTTPException:
                conn.rollback()
                results.append(
                    BulkEndpointResult(
                        row=item.row,
                        address=item.address,
                        label=item.label,
                        status="error",
                        detail="Endereço IP ou CIDR inválido.",
                    )
                )
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                results.append(
                    BulkEndpointResult(
                        row=item.row,
                        address=item.address,
                        label=item.label,
                        status="error",
                        detail="Este endereço já está cadastrado.",
                    )
                )
            except Exception:
                conn.rollback()
                logger.exception("Erro inesperado ao importar endpoint em lote: %r", item.address)
                results.append(
                    BulkEndpointResult(
                        row=item.row,
                        address=item.address,
                        label=item.label,
                        status="error",
                        detail="Erro inesperado ao cadastrar este endereço.",
                    )
                )
    finally:
        conn.close()
    return results


@router.get("")
def list_endpoints(response: Response) -> list[dict]:
    """`is_demo` mesmo padrão de `GET /api/containers` -- só exibição/
    agrupamento no frontend ("Ambiente demonstrativo"/"Ambiente
    operacional"). O critério real de elegibilidade pra publicação
    pública é sempre reconferido ao vivo em routes/demo_host_snapshot.py,
    nunca confiado a partir deste campo.

    `Cache-Control: no-store` -- essa lista muda a cada Descobrir/
    Executar avaliação, e o console admin depende de um reload/refetch
    sempre trazer o estado real, nunca uma resposta em cache do
    navegador/proxy mostrando um endpoint como "nunca avaliado" que já
    foi.
    """
    response.headers.update(_NO_STORE_HEADERS)
    conn = db.connect()
    endpoints = db.select_endpoints(conn)
    conn.close()
    return [{**e, "is_demo": is_demo_endpoint(e["address"])} for e in endpoints]


@router.delete("/{endpoint_id}")
def delete_endpoint(endpoint_id: int) -> dict:
    conn = db.connect()
    deleted = db.delete_endpoint(conn, id=endpoint_id)
    conn.commit()
    conn.close()
    if not deleted:
        raise HTTPException(404, f"endpoint {endpoint_id} not found")
    return {"status": "deleted"}


@router.post("/{endpoint_id}/discover", response_model=list[DiscoveryResult])
def discover_endpoint(endpoint_id: int) -> list[DiscoveryResult]:
    conn = db.connect()
    endpoint = db.select_endpoint_by_id(conn, id=endpoint_id)
    if endpoint is None:
        conn.close()
        raise HTTPException(404, f"endpoint {endpoint_id} not found")

    try:
        results = discovery_client.discover([endpoint["address"]])
    except Exception as e:
        conn.close()
        raise HTTPException(502, f"invariant_discovery request failed: {e}") from e

    scanned_at = datetime.now(timezone.utc).isoformat()
    for result in results:
        db.insert_discovery_result(
            conn,
            endpoint_id=endpoint_id,
            ip=result["ip"],
            classification=result["classification"],
            confidence=result["confidence"],
            evidence=result["evidence"],
            scanned_at=result.get("scanned_at", scanned_at),
        )
    conn.commit()
    conn.close()
    return [DiscoveryResult(**result) for result in results]


@router.get("/{endpoint_id}/results", response_model=list[DiscoveryResult])
def endpoint_results(endpoint_id: int) -> list[DiscoveryResult]:
    conn = db.connect()
    endpoint = db.select_endpoint_by_id(conn, id=endpoint_id)
    if endpoint is None:
        conn.close()
        raise HTTPException(404, f"endpoint {endpoint_id} not found")
    results = db.select_latest_discovery_results_by_endpoint(conn, endpoint_id=endpoint_id)
    conn.close()
    return [
        DiscoveryResult(
            ip=r["ip"],
            classification=r["classification"],
            confidence=r["confidence"],
            evidence=r["evidence"],
            scanned_at=r["scanned_at"].isoformat() if hasattr(r["scanned_at"], "isoformat") else r["scanned_at"],
        )
        for r in results
    ]


def _resolve_target_ip(conn, endpoint_id: int) -> tuple[dict, str]:
    """Shared by /check and /assess: looks up the endpoint and the IP to
    actually connect to. A CIDR endpoint expands to multiple
    discovery_results rows (one per IP) -- both routes act on exactly one
    host per call, deterministically the first discovered row (per-IP
    action across a whole CIDR range is future work, not this phase's
    scope).
    """
    endpoint = db.select_endpoint_by_id(conn, id=endpoint_id)
    if endpoint is None:
        raise HTTPException(404, f"endpoint {endpoint_id} not found")
    discovery_rows = db.select_latest_discovery_results_by_endpoint(conn, endpoint_id=endpoint_id)
    if not discovery_rows:
        raise HTTPException(
            422,
            f"endpoint {endpoint_id} has no discovery results yet -- run POST /endpoints/{endpoint_id}/discover first",
        )
    return endpoint, discovery_rows[0]["ip"]


class SSHCredentials(BaseModel):
    """Request body for POST /endpoints/{id}/assess. Ephemeral,
    request-scoped only -- used once to build this request's
    assessment_client.run_assessment_remote() call, then discarded when
    the request handler returns. Never written to any db.* call in this
    module, never included in any response, never logged.
    """

    port: int = 22
    username: str
    auth_method: str  # "key" | "password"
    key_material: str | None = Field(default=None, repr=False)
    password: str | None = Field(default=None, repr=False)


@router.post("/{endpoint_id}/assess", response_model=list[Finding])
def assess_discovered_endpoint(endpoint_id: int, credentials: SSHCredentials) -> list[Finding]:
    """Runs a real CIS assessment against a discovered endpoint over SSH,
    using credentials supplied in this one request only (never persisted
    -- see SSHCredentials' docstring). The OS/check-family actually
    evaluated is decided by invariant_assessment from the live
    SSH-collected facts, not from discovery_results.classification --
    that classification is a coarse network-fingerprint bucket
    (windows|linux|docker|waf|firewall|vmware|unknown), not precise
    enough to pick a specific CIS document/family.
    """
    conn = db.connect()
    endpoint, target_ip = _resolve_target_ip(conn, endpoint_id)
    conn.close()

    try:
        run = assessment_client.run_assessment_remote(
            host=target_ip,
            port=credentials.port,
            username=credentials.username,
            auth_method=credentials.auth_method,
            key_material=credentials.key_material,
            password=credentials.password,
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text) from e

    findings = _findings_from_run(endpoint["address"], run, target_type="linux_host")

    # Resumo + consumo + evento de domínio numa transação só (ver
    # assessment_runs.persist). Antes, uma falha ao gravar o resumo era só
    # logada; agora a avaliação não conta como concluída se o registro dela
    # (o que inclui a cobrança) não persistir -- devolve 500. O formato da
    # resposta desta rota não muda: list[Finding].
    try:
        assessment_runs.persist(endpoint=endpoint, ip=target_ip, findings=findings, source="console")
    except Exception as e:
        logger.exception("falha ao registrar avaliação do alvo %s", endpoint_id)
        raise HTTPException(500, "falha ao registrar a avaliação") from e
    return findings


@router.post("/{endpoint_id}/assessments")
def create_assessment(
    endpoint_id: int,
    request: v1.AssessmentRequest,
    response: Response,
    username: str = Depends(require_admin_session),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", min_length=1, max_length=200),
) -> dict:
    """Avaliação SSH de um host do alvo, no formato do contrato v1
    (AssessmentEnvelope). Ordem: valida alvo/IP (sem rede) -> reserva a
    Idempotency-Key -> executa fora de transação -> grava resumo, consumo e
    evento juntos. Ver assessment_runs."""
    with db.connect() as conn:
        endpoint, ip = assessment_runs.resolve_target(conn, endpoint_id, request.ip)
    principal = f"admin:{username}"
    if idempotency_key is not None:
        fp = assessment_runs.fingerprint(assessment_runs.CREATE_ROUTE, endpoint_id, request)
        replay = assessment_runs.reserve(principal, idempotency_key, assessment_runs.CREATE_ROUTE, fp)
        if replay is not None:
            response.status_code = replay["status"]
            return replay["body"]
    try:
        run = assessment_runs.run_remote(ip, request.ssh)
        findings = _findings_from_run(endpoint["address"], run, target_type="linux_host")
        return assessment_runs.persist(
            endpoint=endpoint, ip=ip, findings=findings, source="console",
            idempotency=None if idempotency_key is None else (principal, idempotency_key),
        )
    except Exception as e:
        # Nada persistido (falha antes ou dentro da transação, que é
        # desfeita inteira): a chave volta a valer para uma nova tentativa.
        if idempotency_key is not None:
            assessment_runs.release(principal, idempotency_key)
        if isinstance(e, HTTPException):
            raise
        logger.exception("falha ao registrar avaliação do alvo %s", endpoint_id)
        raise assessment_runs.api_error(500, v1.ErrorCode.internal_error, "falha ao registrar a avaliação") from e


def _list_item(row: dict) -> dict:
    return v1.AssessmentListItem(
        assessment_id=row["public_id"],
        target_id=row["endpoint_id"],
        assessed_ip=row["assessed_ip"],
        assessed_at=row["assessed_at"],
        source=row["source"],
        summary=_summary(row),
        findings_stored=False,
    ).model_dump(mode="json")


def _summary(row: dict) -> v1.Summary:
    return v1.Summary(
        passed=row["pass_count"],
        failed=row["fail_count"],
        not_assessed=row["not_assessed_count"],
        not_applicable=row["not_applicable_count"],
        compliance_pct=row["compliance_pct"],
    )


@router.get("/{endpoint_id}/assessments")
def list_assessments(endpoint_id: int) -> list[dict]:
    """Avaliações do alvo, mais recentes primeiro. Linhas antigas de alvos
    CIDR sem assessed_ip registrado (anteriores à F1) ficam de fora."""
    with db.connect() as conn:
        if db.select_endpoint_by_id(conn, id=endpoint_id) is None:
            raise assessment_runs.api_error(404, v1.ErrorCode.not_found, f"alvo {endpoint_id} não encontrado")
        rows = db.select_assessments_by_endpoint(conn, endpoint_id=endpoint_id)
    return [_list_item(r) for r in rows if r["assessed_ip"]]


@router.get("/{endpoint_id}/assessments/{assessment_id}")
def get_assessment(endpoint_id: int, assessment_id: UUID) -> dict:
    """Resumo de uma avaliação. Achados não são guardados nesta versão
    (findings=null, findings_omitted_reason=not_stored)."""
    with db.connect() as conn:
        row = db.select_assessment_by_public_id(conn, endpoint_id=endpoint_id, public_id=assessment_id)
    if row is None or not row["assessed_ip"]:
        raise assessment_runs.api_error(404, v1.ErrorCode.not_found, "avaliação não encontrada")
    return assessment_runs.envelope(
        public_id=row["public_id"], endpoint_id=row["endpoint_id"], assessed_ip=row["assessed_ip"],
        assessed_at=row["assessed_at"], source=row["source"], summary=_summary(row).model_dump(),
        findings=None, omitted_reason="not_stored",
    )


@router.post("/{endpoint_id}/check")
def check_endpoint(endpoint_id: int, credentials: SSHCredentials) -> dict:
    """Cheap pre-flight for POST /{endpoint_id}/assess -- same idea as
    GET /containers/{name}/check, but for an SSH-reached Linux host:
    identifies target_type/hostname/OS/primary IP before committing to a
    real assessment run. `primary_ip` is the endpoint's own stored
    address -- never asked of invariant_assessment, since invariant_api
    already owns that data.
    """
    conn = db.connect()
    endpoint, target_ip = _resolve_target_ip(conn, endpoint_id)
    conn.close()
    try:
        result = assessment_client.check_remote(
            host=target_ip,
            port=credentials.port,
            username=credentials.username,
            auth_method=credentials.auth_method,
            key_material=credentials.key_material,
            password=credentials.password,
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text) from e
    return {**result, "target_type": "linux_host", "primary_ip": endpoint["address"]}
