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

from fastapi import APIRouter, Depends, HTTPException
from invariant_contracts import DiscoveryResult, Endpoint

from invariant_api.auth import require_admin_session
from invariant_api.clients import discovery_client
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
