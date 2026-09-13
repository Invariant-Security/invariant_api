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

    # Explicit status filters, not "anything not FAIL counts as PASS" (or
    # vice versa) -- today's pipeline only ever produces PASS/FAIL, but
    # this must stay correct if a third status (e.g. "NOT ASSESSED") ever
    # shows up, rather than silently mis-stating the total.
    passed = [f for f in findings if f.status == "PASS"]
    failed = [f for f in findings if f.status == "FAIL"]
    other = [f for f in findings if f.status not in ("PASS", "FAIL")]
    level1_failed = _sorted_by_level([f for f in failed if f.level == 1])
    total = len(findings)
    pct = round(100 * len(passed) / total) if total else 0

    summary = f"{total} controls evaluated against CIS benchmarks. {pct}% compliant ({len(passed)} passed / {len(failed)} failed"
    summary += f" / {len(other)} not assessed" if other else ""
    summary += ")."

    story = _cover(title, "Executive Summary")
    story.append(Paragraph(summary, _styles["Normal"]))
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


# NOT a table. A real assessment's remediation text runs well past 4000
# characters on some controls (checked live against tamois's 199-control
# run) -- squeezed into a ~1.75in table column that wraps into a single
# row taller than a whole page, which reportlab's Table.split() cannot
# break (LayoutError: "too large"), no matter how few rows share that
# table. Free-flowing Paragraphs per finding have no such ceiling: each
# one splits across a page boundary on its own like any body text.
_FINDING_HEADER_STYLE = ParagraphStyle("finding_header", parent=_styles["Heading3"], spaceBefore=10, spaceAfter=2)
_FINDING_META_STYLE = ParagraphStyle("finding_meta", parent=_styles["Normal"], fontSize=8, textColor=colors.grey)
_FINDING_LABEL_STYLE = ParagraphStyle(
    "finding_label", parent=_styles["Normal"], fontSize=8, textColor=colors.grey, spaceBefore=6
)
_FINDING_BODY_STYLE = ParagraphStyle("finding_body", parent=_styles["Normal"], fontSize=9, leading=12)
_STATUS_COLOR = {"PASS": "#0f6b3f", "FAIL": "#b91c1c"}


def build_technical_report(title: str, findings: list[Finding]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"Invariant — {title} — Technical")

    story = _cover(title, "Technical Report — full findings")
    for f in _sorted_by_level(findings):
        level_text = f"L{f.level}" if f.level is not None else "—"
        status_color = _STATUS_COLOR.get(f.status, "#000000")
        story.append(
            Paragraph(
                f'<font color="{status_color}"><b>{escape(f.status)}</b></font> '
                f"{escape(f.external_id)} — {escape(f.control_title)} ({level_text})",
                _FINDING_HEADER_STYLE,
            )
        )
        story.append(
            Paragraph(
                f"{escape(f.source_name)}/{escape(f.document_name)} v{escape(f.document_version)}",
                _FINDING_META_STYLE,
            )
        )
        story.append(Paragraph("Evidence", _FINDING_LABEL_STYLE))
        story.append(Paragraph(escape(f.evidence_output) or "—", _FINDING_BODY_STYLE))
        if f.remediation:
            story.append(Paragraph("Remediation", _FINDING_LABEL_STYLE))
            story.append(Paragraph(escape(f.remediation), _FINDING_BODY_STYLE))

    doc.build(story)
    return buf.getvalue()
