"""Turns a list of Finding (already in the frontend's hands after an
assess call -- no re-fetch, no Postgres) into a downloadable PDF. See
invariant_api/reports.py for the actual document-building logic.
"""

from typing import Literal

from fastapi import APIRouter, Response
from invariant_contracts import Finding
from pydantic import BaseModel

from invariant_api.reports import build_ceo_report, build_technical_report

router = APIRouter()


class ReportRequest(BaseModel):
    title: str
    kind: Literal["ceo", "technical"]
    findings: list[Finding]


@router.post("/reports/pdf")
def generate_report(payload: ReportRequest) -> Response:
    builder = build_ceo_report if payload.kind == "ceo" else build_technical_report
    pdf_bytes = builder(payload.title, payload.findings)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="invariant-{payload.kind}-report.pdf"'},
    )
