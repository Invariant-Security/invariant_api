"""Orchestrates invariant_assessment (evaluate) + Postgres (real CIS
control metadata) to build a Finding -- the Opção B communication design
agreed with the project owner: 1 round-trip to invariant_assessment, this
route does the join. This is the exact body of the monolith's
assess_target()'s `for check in CHECKS` loop, moved here unchanged --
only its inputs changed (a list of {titles, status, evidence} dicts from
an HTTP call instead of iterating CHECKS/facts directly).
"""

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException
from invariant_contracts import Finding

from invariant_api.clients import assessment_client
from invariant_api.storage import postgres as db

router = APIRouter()


def _control_level(normalized_data: dict) -> int | None:
    """Minimum `level` across a control's `applicability` list -- same
    logic as the monolith's assessment._control_level(), just realocated
    here since this is now the only invariant_* service with Postgres
    access to a control's normalized_data.
    """
    levels = [a["level"] for a in normalized_data.get("applicability") or [] if a.get("level") is not None]
    return min(levels) if levels else None


def _findings_from_run(target_label: str, run: dict) -> list[Finding]:
    """Turns invariant_assessment's {document, results: [...]}  response
    into real Findings by joining each result against Postgres control
    metadata by title. Shared by both the docker-exec assess route
    (assess()) and the SSH-based endpoints.assess_discovered_endpoint()
    route -- same join, different caller/target_label/assessment_client
    function used to produce `run`.
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
    return _findings_from_run(target, run)
