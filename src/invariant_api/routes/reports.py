"""Turns a list of Finding (already in the frontend's hands after an
assess call -- no re-fetch, no Postgres) into a downloadable PDF. See
invariant_api/reports.py for the actual document-building logic.
"""

from typing import Literal

from fastapi import APIRouter, Response
from invariant_contracts import Finding
from pydantic import BaseModel

from invariant_api.reports import ConsolidatedAsset, build_ceo_report, build_consolidated_report, build_technical_report

router = APIRouter()


class AssetPayload(BaseModel):
    name: str
    status: Literal["success", "error"]
    findings: list[Finding] = []
    error: str | None = None


class ReportRequest(BaseModel):
    title: str
    kind: Literal["ceo", "technical", "consolidated"]
    findings: list[Finding] = []
    assets: list[AssetPayload] = []


@router.post("/reports/pdf")
def generate_report(payload: ReportRequest) -> Response:
    if payload.kind == "consolidated":
        pdf_bytes = build_consolidated_report(
            [ConsolidatedAsset(name=a.name, status=a.status, findings=a.findings, error=a.error) for a in payload.assets]
        )
    else:
        builder = build_ceo_report if payload.kind == "ceo" else build_technical_report
        pdf_bytes = builder(payload.title, payload.findings)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="invariant-{payload.kind}-report.pdf"'},
    )
