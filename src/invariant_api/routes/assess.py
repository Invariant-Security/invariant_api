"""Orchestrates invariant_assessment (evaluate) + Postgres (real CIS
control metadata) to build a Finding -- the Opção B communication design
agreed with the project owner: 1 round-trip to invariant_assessment, this
route does the join. This is the exact body of the monolith's
assess_target()'s `for check in CHECKS` loop, moved here unchanged --
only its inputs changed (a list of {titles, status, evidence} dicts from
an HTTP call instead of iterating CHECKS/facts directly).

Guardado por require_admin_session -- estas rotas rodam docker exec de
verdade contra containers reais deste host (issue #3, corrigida agora
que /containers também é ponto de entrada da demo pública: visitante
nunca pode chegar aqui, só no /demo-snapshot já sanitizado).
"""

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Response
from invariant_contracts import Finding

from invariant_api.auth import require_admin_session
from invariant_api.clients import assessment_client
from invariant_api.storage import postgres as db

router = APIRouter(dependencies=[Depends(require_admin_session)])


def _control_level(normalized_data: dict) -> int | None:
    """Minimum `level` across a control's `applicability` list -- same
    logic as the monolith's assessment._control_level(), just realocated
    here since this is now the only invariant_* service with Postgres
    access to a control's normalized_data.
    """
    levels = [a["level"] for a in normalized_data.get("applicability") or [] if a.get("level") is not None]
    return min(levels) if levels else None


def _findings_from_run(target_label: str, run: dict, target_type: str) -> list[Finding]:
    """Turns invariant_assessment's {document, results: [...]}  response
    into real Findings by joining each result against Postgres control
    metadata by title. Shared by both the docker-exec assess route
    (assess()) and the SSH-based endpoints.assess_discovered_endpoint()
    route -- same join, different caller/target_label/assessment_client
    function used to produce `run`. `target_type` is decided by the caller
    (which route/transport was used), never inferred here -- feeds
    finding_taxonomy's applicability logic (HOST_ONLY_CONTROLS only
    applies to docker_container, never a real linux_host).
    """
    conn = db.connect()
    collected_at = datetime.now(timezone.utc).isoformat()
    findings = []
    for result in run["results"]:
        control = db.select_control_by_title(conn, document=run["document"], titles=result["titles"])
        if control is None:
            conn.close()
            raise HTTPException(422, f"none of {result['titles']!r} found for document {run['document']!r}")
        findings.append(
            Finding(
                target=target_label,
                external_id=control["external_id"],
                status=result["status"],
                control_title=control["title"],
                source_name=control["source_name"],
                document_name=control["document_name"],
                document_version=control["publisher_version"],
                evidence_output=result["evidence"],
                collected_at=collected_at,
                remediation=control["normalized_data"].get("remediation", ""),
                raw_artifact_path=control["raw_artifact_path"] or "",
                content_hash=control["content_hash"] or "",
                level=_control_level(control["normalized_data"]),
                scored=control["normalized_data"].get("scored"),
                document_retrieved_at=(
                    control["retrieved_at"].isoformat() if control["retrieved_at"] else ""
                ),
                target_type=target_type,
            )
        )
    conn.close()
    return findings


@router.post("/assess/{target}", response_model=list[Finding])
def assess(target: str) -> list[Finding]:
    try:
        run = assessment_client.run_assessment(target)
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text) from e
    return _findings_from_run(target, run, target_type="docker_container")


@router.get("/containers")
def list_containers() -> list[dict]:
    """Candidates for POST /assess/{target} -- every container on this
    host, minus invariant's own stack (appliance/demo/infra, not a client
    asset -- the "invariant-" prefix is a naming convention this project
    controls, not a guess).
    """
    containers = assessment_client.list_containers()
    return [c for c in containers if not c["name"].startswith("invariant-")]


@router.get("/containers/{name}/check")
def check_container(name: str, response: Response) -> dict:
    """Cheap pre-flight for POST /assess/{name} -- detects OS, checks it
    against the same family_for_os() gate assess() itself hits, but never
    runs the 199 CHECKS. GET is semantically fine here (a read of the
    container's current, discoverable state), but that state can change
    if the container gets recreated under the same name -- no-store keeps
    an intermediary from serving a stale answer.
    """
    response.headers["Cache-Control"] = "no-store"
    try:
        result = assessment_client.check_target(name)
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text) from e
    return {**result, "target_type": "docker_container", "primary_ip": None}
