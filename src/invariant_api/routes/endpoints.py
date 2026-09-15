"""CRUD de endpoints (IP individual ou CIDR) + gatilho de discovery.
Guardado por require_admin_session -- diferente de assess/ingest/demo, que
continuam sem auth, de propósito, fora de escopo desta etapa.

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

import httpx
import psycopg
from fastapi import APIRouter, Depends, HTTPException
from invariant_contracts import DiscoveryResult, Endpoint, Finding
from pydantic import BaseModel, Field

from invariant_api.auth import require_admin_session
from invariant_api.clients import assessment_client, discovery_client
from invariant_api.routes.assess import _findings_from_run
from invariant_api.storage import postgres as db

router = APIRouter(prefix="/endpoints", dependencies=[Depends(require_admin_session)])

logger = logging.getLogger(__name__)

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
def list_endpoints() -> list[dict]:
    conn = db.connect()
    endpoints = db.select_endpoints(conn)
    conn.close()
    return endpoints


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

    return _findings_from_run(endpoint["address"], run, target_type="linux_host")


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
