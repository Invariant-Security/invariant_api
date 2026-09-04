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
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from invariant_contracts import DiscoveryResult, Endpoint, Finding
from pydantic import BaseModel, Field

from invariant_api.auth import require_admin_session
from invariant_api.clients import assessment_client, discovery_client
from invariant_api.routes.assess import _findings_from_run
from invariant_api.storage import postgres as db

router = APIRouter(prefix="/endpoints", dependencies=[Depends(require_admin_session)])


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
    endpoint = db.select_endpoint_by_id(conn, id=endpoint_id)
    if endpoint is None:
        conn.close()
        raise HTTPException(404, f"endpoint {endpoint_id} not found")

    discovery_rows = db.select_latest_discovery_results_by_endpoint(conn, endpoint_id=endpoint_id)
    conn.close()
    if not discovery_rows:
        raise HTTPException(
            422,
            f"endpoint {endpoint_id} has no discovery results yet -- run POST /endpoints/{endpoint_id}/discover first",
        )
    # A CIDR endpoint expands to multiple discovery_results rows (one per
    # IP) -- this route assesses exactly one host per call, deterministically
    # the first discovered row. Per-IP assessment across a whole CIDR range
    # is future work, not this phase's scope.
    target_ip = discovery_rows[0]["ip"]

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

    return _findings_from_run(endpoint["address"], run)
