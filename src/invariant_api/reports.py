"""PDF report generation from a list of Finding -- two audiences, same
input data. CEO report: pass/fail summary + control titles only, no raw
evidence/remediation text (that's what makes it readable by a
non-technical exec). Technical report: every finding, full detail, for
whoever actually fixes things.

Pure functions, no Postgres/HTTP here -- routes/reports.py is the only
caller, same separation invariant_api's other report-shaped modules
(reports.py itself has no precedent yet, but assess.py/ingest.py keep the
same "orchestration in routes, logic elsewhere" split).
"""

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from invariant_contracts import Finding
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

_styles = getSampleStyleSheet()
_TABLE_HEADER_STYLE = [
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d2b4f")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
]


def _sorted_by_level(findings: list[Finding]) -> list[Finding]:
    # Same ordering as the frontend's byLevel() in src/findings.jsx --
    # CIS Level 1 (baseline) before Level 2 before "no applicability data".
    return sorted(findings, key=lambda f: f.level if f.level is not None else 99)


def _cover(title: str, subtitle: str) -> list:
    return [
        Paragraph("Invariant Security Assessment", _styles["Title"]),
        Paragraph(escape(title), _styles["Heading2"]),
        Paragraph(escape(subtitle), _styles["Normal"]),
        Paragraph(datetime.now(timezone.utc).strftime("%Y-%m-%d"), _styles["Normal"]),
        Spacer(1, 0.3 * inch),
    ]


def build_ceo_report(title: str, findings: list[Finding]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"Invariant — {title}")

    passed = [f for f in findings if f.status == "PASS"]
    failed = [f for f in findings if f.status == "FAIL"]
    level1_failed = _sorted_by_level([f for f in failed if f.level == 1])
    total = len(findings)
    pct = round(100 * len(passed) / total) if total else 0

    story = _cover(title, "Executive Summary")
    story.append(
        Paragraph(
            f"{total} controls evaluated against CIS benchmarks. "
            f"{pct}% compliant ({len(passed)} passed / {len(failed)} failed).",
            _styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.15 * inch))
    story.append(
        Paragraph(
            f"{len(level1_failed)} high-priority (CIS Level 1) issue(s) require attention."
            if level1_failed
            else "No high-priority (CIS Level 1) issues found.",
            _styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.3 * inch))

    if level1_failed:
        story.append(Paragraph("Top Priority Issues", _styles["Heading2"]))
        rows = [["Control"]] + [[escape(f.control_title)] for f in level1_failed]
        table = Table(rows, colWidths=[6.5 * inch])
        table.setStyle(TableStyle(_TABLE_HEADER_STYLE + [("FONTSIZE", (0, 0), (-1, -1), 9)]))
        story.append(table)

    doc.build(story)
    return buf.getvalue()


def build_technical_report(title: str, findings: list[Finding]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"Invariant — {title} — Technical")

    story = _cover(title, "Technical Report — full findings")
    cell_style = ParagraphStyle("cell", parent=_styles["Normal"], fontSize=8, leading=10)
    rows = [["ID", "Control", "Status", "Level", "Evidence", "Remediation"]]
    for f in _sorted_by_level(findings):
        rows.append(
            [
                Paragraph(escape(f.external_id), cell_style),
                Paragraph(escape(f.control_title), cell_style),
                f.status,
                str(f.level) if f.level is not None else "-",
                Paragraph(escape(f.evidence_output), cell_style),
                Paragraph(escape(f.remediation) if f.remediation else "-", cell_style),
            ]
        )
    table = Table(
        rows,
        colWidths=[0.55 * inch, 1.55 * inch, 0.5 * inch, 0.4 * inch, 1.75 * inch, 1.75 * inch],
        repeatRows=1,
    )
    table.setStyle(TableStyle(_TABLE_HEADER_STYLE + [("FONTSIZE", (0, 0), (-1, -1), 8)]))
    story.append(table)

    doc.build(story)
    return buf.getvalue()
