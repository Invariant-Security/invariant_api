"""PDF report generation from a list of Finding -- two audiences, same
input data. CEO report: executive posture + risk summary + narrative key
risks by domain, no raw evidence/remediation text. Technical report:
every finding, full detail, organized so "what failed and how do I fix
it" comes first and "everything that passed" is an appendix.

See finding_taxonomy.py for the two classifications both reports lean on:
`classify_domain` (cosmetic grouping) and `classify_environment` (whether
a control even applies to a Docker container -- feeds the compliance %
directly, so it's a reviewed lookup table, not a runtime heuristic).

Pure functions, no Postgres/HTTP here -- routes/reports.py is the only
caller, same separation invariant_api's other report-shaped modules
(reports.py itself has no precedent yet, but assess.py/ingest.py keep the
same "orchestration in routes, logic elsewhere" split).
"""

import io
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import NamedTuple
from xml.sax.saxutils import escape

from invariant_contracts import Finding
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Flowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from invariant_api.finding_taxonomy import (
    DOMAIN_NARRATIVE,
    SSHD_DEPENDENT_CONTROLS,
    classify_domain,
    classify_environment,
    ssh_state,
)

_styles = getSampleStyleSheet()
_TABLE_HEADER_STYLE = [
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d2b4f")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
]
_PLAIN_TABLE_STYLE = [
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
]


def _sorted_by_level(findings: list[Finding]) -> list[Finding]:
    # Same ordering as the frontend's byLevel() in src/findings.jsx --
    # CIS Level 1 (baseline) before Level 2 before "no applicability data".
    return sorted(findings, key=lambda f: f.level if f.level is not None else 99)


def _format_os_display(document_name: str) -> str:
    """Deterministic parse, not free-text heuristics -- document_name is
    an internal identifier this project controls, always shaped
    "{distro}_linux_{version}" (e.g. "debian_linux_12",
    "ubuntu_linux_24_04"). Never guesses; an unrecognized shape just
    falls back to the raw string rather than raising.
    """
    if "_linux_" not in document_name:
        return document_name
    distro, _, version = document_name.partition("_linux_")
    return f"{distro.capitalize()} {version.replace('_', '.')}"


def _format_target_label(
    target_type: str,
    document_name: str,
    hostname: str | None = None,
    primary_ip: str | None = None,
    container_image: str | None = None,
) -> str:
    """Builds the one-line target identity shown on every report cover --
    "Linux host · Debian 13 · 10.0.0.25" or "Docker container · Debian
    13" or "Docker container · PostgreSQL 16 · Debian 12". hostname/
    primary_ip are deliberately ignored for docker_container even if a
    caller passes them by mistake -- IP/hostname are never a container
    concept in this design, so this is the one place that guarantees they
    can't leak onto a container's report regardless of what the request
    body contained.
    """
    kind = "Linux host" if target_type == "linux_host" else "Docker container"
    parts = [kind]
    if container_image:
        parts.append(container_image)
    os_display = _format_os_display(document_name) if document_name else None
    if os_display:
        parts.append(os_display)
    if target_type == "linux_host":
        parts.append(primary_ip or "Unknown")
    return " · ".join(parts)


def _cover(
    title: str,
    subtitle: str,
    findings: list[Finding] | None = None,
    hostname: str | None = None,
    primary_ip: str | None = None,
    container_image: str | None = None,
) -> list:
    story = [
        Paragraph("Invariant Security Assessment", _styles["Title"]),
        Paragraph(escape(title), _styles["Heading2"]),
        Paragraph(escape(subtitle), _styles["Normal"]),
        Paragraph(datetime.now(timezone.utc).strftime("%Y-%m-%d"), _styles["Normal"]),
    ]
    if findings:
        label = _format_target_label(
            findings[0].target_type, findings[0].document_name, hostname, primary_ip, container_image
        )
        story.append(Paragraph(escape(label), _styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))
    return story


def split_findings(findings: list[Finding]):
    """Buckets every finding into exactly one of four groups, checked in
    this priority order: a status outside PASS/FAIL always means "not
    assessed" regardless of environment (today's pipeline never produces
    a third status, but this must not assume it never will); otherwise a
    host-only control is "not applicable" -- but ONLY for a
    docker_container target: HOST_ONLY_CONTROLS means "not applicable to
    the container context", not "globally irrelevant" -- a real Linux
    host (target_type="linux_host") must be judged on GRUB/auditd/
    journald/cron/partitions normally, the same as any other control.
    Likewise an SSH-dependent control is "not applicable" when this
    target's sshd is confirmed ABSENT (never merely UNKNOWN -- see
    ssh_state()'s docstring; a probe failure of unclear cause must never
    silently remove real findings) -- this check IS unconditional on
    target_type, since "is sshd installed" is a real question for a host
    too, not a container-only concept. Otherwise it's a real PASS or FAIL.
    Returns (applicable_pass, applicable_fail, not_assessed, not_applicable).
    """
    applicable_pass: list[Finding] = []
    applicable_fail: list[Finding] = []
    not_assessed: list[Finding] = []
    not_applicable: list[Finding] = []
    state = ssh_state(findings)
    target_type = findings[0].target_type if findings else "docker_container"
    for f in findings:
        is_ssh_absent = state == "absent" and (f.document_name, f.external_id) in SSHD_DEPENDENT_CONTROLS
        is_host_only_for_container = target_type == "docker_container" and classify_environment(f) == "host_only"
        if f.status not in ("PASS", "FAIL"):
            not_assessed.append(f)
        elif is_host_only_for_container or is_ssh_absent:
            not_applicable.append(f)
        elif f.status == "FAIL":
            applicable_fail.append(f)
        else:
            applicable_pass.append(f)
    return applicable_pass, applicable_fail, not_assessed, not_applicable


def compliance_pct(applicable_pass: list[Finding], applicable_fail: list[Finding]) -> int | None:
    """None means "nothing applicable was actually evaluated" -- render
    as "N/A", never "0%" (0% asserts "everything evaluated failed",  a
    different and stronger claim).
    """
    evaluated = len(applicable_pass) + len(applicable_fail)
    return round(100 * len(applicable_pass) / evaluated) if evaluated else None


def _bar_fill_width(pct: int | None, total_width: float) -> float:
    if not pct:
        return 0.0
    return total_width * pct / 100


class _ComplianceBar(Flowable):
    """A real filled rectangle, proportional to `pct` -- a text/Unicode
    bar (the previous approach) renders inconsistently across viewers and
    visually looked nearly full even at ~56%, since block characters don't
    subdivide finely and font rendering varies. `pct=None`/`0` draws a
    fully empty bar, never a filled one (matches "N/A"/"0%" never being
    conflated with a filled bar).
    """

    def __init__(self, pct: int | None, width: float = 4 * inch, height: float = 0.22 * inch):
        super().__init__()
        self.pct = pct
        self.width = width
        self.height = height

    def wrap(self, avail_width, avail_height):
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(colors.HexColor("#e5e7eb"))
        c.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        filled = _bar_fill_width(self.pct, self.width)
        if filled:
            c.setFillColor(colors.HexColor("#1d2b4f"))
            c.rect(0, 0, filled, self.height, fill=1, stroke=0)
        c.setStrokeColor(colors.grey)
        c.rect(0, 0, self.width, self.height, fill=0, stroke=1)


def _summary_line(applicable_pass, applicable_fail, not_assessed, not_applicable, total: int, pct_text: str) -> str:
    parts = f"{len(applicable_pass)} passed / {len(applicable_fail)} failed"
    if not_assessed:
        parts += f" / {len(not_assessed)} not assessed"
    if not_applicable:
        parts += f" / {len(not_applicable)} not applicable"
    return f"{total} controls evaluated against CIS benchmarks. {pct_text} compliant ({parts})."


def build_ceo_report(
    title: str,
    findings: list[Finding],
    hostname: str | None = None,
    primary_ip: str | None = None,
    container_image: str | None = None,
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"Invariant — {title}")

    applicable_pass, applicable_fail, not_assessed, not_applicable = split_findings(findings)
    pct = compliance_pct(applicable_pass, applicable_fail)
    pct_text = "N/A" if pct is None else f"{pct}%"

    story = _cover(title, "Executive Summary", findings, hostname, primary_ip, container_image)
    story.append(
        Paragraph(
            _summary_line(applicable_pass, applicable_fail, not_assessed, not_applicable, len(findings), pct_text),
            _styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    bar_row = Table(
        [[_ComplianceBar(pct), Paragraph(f"{pct_text} compliant", _styles["Normal"])]],
        colWidths=[4.2 * inch, 2 * inch],
    )
    bar_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(bar_row)
    story.append(Spacer(1, 0.3 * inch))

    level1 = [f for f in applicable_fail if f.level == 1]
    level2 = [f for f in applicable_fail if f.level == 2]
    other_level = [f for f in applicable_fail if f.level not in (1, 2)]

    story.append(Paragraph("Risk Summary", _styles["Heading2"]))
    risk_rows = [
        ["CIS Level 1 failures", str(len(level1))],
        ["CIS Level 2 failures", str(len(level2))],
        ["Other failures", str(len(other_level))],
        ["Not Applicable", str(len(not_applicable))],
    ]
    risk_table = Table(risk_rows, colWidths=[4.5 * inch, 2 * inch])
    risk_table.setStyle(TableStyle(_PLAIN_TABLE_STYLE))
    story.append(risk_table)
    story.append(Spacer(1, 0.3 * inch))

    domain_counts = Counter(classify_domain(f.control_title) for f in applicable_fail)
    top_domains = domain_counts.most_common(4)
    if top_domains:
        story.append(Paragraph("Key Risks", _styles["Heading2"]))
        for i, (domain, count) in enumerate(top_domains, start=1):
            story.append(Paragraph(f"{i}. {escape(domain)} ({count})", _styles["Heading3"]))
            story.append(Paragraph(escape(DOMAIN_NARRATIVE.get(domain, DOMAIN_NARRATIVE["Other"])), _styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Recommended Next Actions", _styles["Heading2"]))
    actions = []
    if top_domains:
        top_names = " and ".join(d for d, _ in top_domains[:2])
        actions.append(f"Address {top_names} findings first.")
    actions.append("Review authentication and access policies.")
    actions.append("Validate environment applicability before treating Not Applicable items as resolved.")
    actions.append("Re-run this assessment after remediation.")
    for action in actions:
        story.append(Paragraph(f"• {escape(action)}", _styles["Normal"]))

    doc.build(story)
    return buf.getvalue()


# NOT a table for full findings. A real assessment's remediation text runs
# well past 4000 characters on some controls (checked live against
# tamois's 199-control run) -- squeezed into a ~1.75in table column that
# wraps into a single row taller than a whole page, which reportlab's
# Table.split() cannot break (LayoutError: "too large"), no matter how few
# rows share that table. Free-flowing Paragraphs per finding have no such
# ceiling: each one splits across a page boundary on its own like any body
# text. Short, uniform rows (Not Applicable / Passed Controls, id+title
# only, no evidence/remediation) stay as plain tables -- no single cell
# there is at risk of that failure mode.
_FINDING_HEADER_STYLE = ParagraphStyle("finding_header", parent=_styles["Heading3"], spaceBefore=10, spaceAfter=2)
_FINDING_META_STYLE = ParagraphStyle("finding_meta", parent=_styles["Normal"], fontSize=8, textColor=colors.grey)
_FINDING_LABEL_STYLE = ParagraphStyle(
    "finding_label", parent=_styles["Normal"], fontSize=8, textColor=colors.grey, spaceBefore=6
)
_FINDING_BODY_STYLE = ParagraphStyle("finding_body", parent=_styles["Normal"], fontSize=9, leading=12)
_FINDING_WHY_STYLE = ParagraphStyle(
    "finding_why", parent=_FINDING_BODY_STYLE, textColor=colors.grey, fontName="Helvetica-Oblique"
)
_STATUS_COLOR = {"PASS": "#0f6b3f", "FAIL": "#b91c1c"}


def _append_finding_detail(story: list, f: Finding) -> None:
    level_text = f"L{f.level}" if f.level is not None else "—"
    status_color = _STATUS_COLOR.get(f.status, "#000000")
    domain = classify_domain(f.control_title)
    story.append(
        Paragraph(
            f'<font color="{status_color}"><b>{escape(f.status)}</b></font> '
            f"{escape(f.external_id)} — {escape(f.control_title)} ({level_text})",
            _FINDING_HEADER_STYLE,
        )
    )
    story.append(
        Paragraph(
            f"{escape(domain)} · {escape(f.source_name)}/{escape(f.document_name)} v{escape(f.document_version)}",
            _FINDING_META_STYLE,
        )
    )
    story.append(Paragraph("Evidence", _FINDING_LABEL_STYLE))
    story.append(Paragraph(escape(f.evidence_output) or "—", _FINDING_BODY_STYLE))
    if f.remediation:
        story.append(Paragraph("Remediation", _FINDING_LABEL_STYLE))
        story.append(Paragraph(escape(f.remediation), _FINDING_BODY_STYLE))


def _compact_control_table(findings: list[Finding], extra_col: str | None = None) -> Table:
    header = ["ID", "Control"] + ([extra_col] if extra_col else [])
    rows = [header]
    for f in _sorted_by_level(findings):
        # Plain Table cells (unlike Paragraph) never parse markup, so
        # escape() here would leave literal "&amp;" etc. on the page --
        # see the same reasoning at the other Table row-builders below.
        row = [f.external_id, f.control_title]
        if extra_col:
            row.append(f.status)
        rows.append(row)
    col_widths = [0.8 * inch, 5.5 * inch] if not extra_col else [0.7 * inch, 4.9 * inch, 0.7 * inch]
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
    return table


def _not_applicable_table(findings: list[Finding]) -> Table:
    """Not Applicable is never a raw PASS/FAIL outcome -- every row here
    was excluded from compliance, so "Effective Status" is always the
    literal "N/A"; "Raw Result" keeps the underlying PASS/FAIL only for
    auditability (so a reader can tell the check genuinely ran, it just
    didn't count).
    """
    rows = [["ID", "Control", "Effective Status", "Raw Result"]]
    for f in _sorted_by_level(findings):
        rows.append([f.external_id, f.control_title, "N/A", f.status])
    table = Table(rows, colWidths=[0.7 * inch, 4.3 * inch, 1.0 * inch, 0.8 * inch], repeatRows=1)
    table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
    return table


class ConsolidatedAsset(NamedTuple):
    """One container's outcome from a batch "Run selected" -- `findings`
    is empty when `status == "error"` (the individual assessment call
    itself failed; `error` carries why). routes/reports.py builds these
    from the request body; kept as a plain NamedTuple here (not the
    request's pydantic model) so this module stays free of API-layer
    concerns.
    """

    name: str
    status: str  # "success" | "error"
    findings: list[Finding]
    error: str | None


def build_consolidated_report(assets: list[ConsolidatedAsset]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title="Invariant — Consolidated Assessment")

    succeeded = [a for a in assets if a.status == "success"]
    errored = [a for a in assets if a.status != "success"]

    story = _cover("Consolidated Assessment", "Fleet Overview")

    story.append(Paragraph("Executive Overview", _styles["Heading2"]))
    story.append(
        Paragraph(
            f"{len(assets)} selected / {len(succeeded)} assessed / {len(errored)} failed.",
            _styles["Normal"],
        )
    )
    if errored:
        names = ", ".join(escape(a.name) for a in errored)
        story.append(Paragraph(f"Failed to assess: {names}", _styles["Normal"]))

    # Computed once per asset, reused below for both the overview totals
    # and Compliance by Asset -- split_findings is the single source of
    # truth for what counts as processed/applicable/not-applicable.
    per_asset = [(a.name, split_findings(a.findings)) for a in succeeded]

    processed = sum(len(a.findings) for a in succeeded)
    applicable_total = sum(len(ap) + len(af) for _, (ap, af, _, _) in per_asset)
    not_applicable_total = sum(len(na) for _, (_, _, _, na) in per_asset)
    not_assessed_total = sum(len(nas) for _, (_, _, nas, _) in per_asset)
    benchmarks = sorted({f"{f.document_name} v{f.document_version}" for a in succeeded for f in a.findings})
    story.append(Paragraph(f"Controls processed: {processed}", _styles["Normal"]))
    story.append(Paragraph(f"Applicable controls: {applicable_total}", _styles["Normal"]))
    story.append(Paragraph(f"Not Applicable: {not_applicable_total}", _styles["Normal"]))
    if not_assessed_total:
        story.append(Paragraph(f"Not Assessed: {not_assessed_total}", _styles["Normal"]))
    if benchmarks:
        story.append(Paragraph(f"Benchmarks: {escape(', '.join(benchmarks))}", _styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))

    if not succeeded:
        doc.build(story)
        return buf.getvalue()

    story.append(Paragraph("Compliance by Asset", _styles["Heading2"]))
    asset_pct = [(name, compliance_pct(ap, af)) for name, (ap, af, _, _) in per_asset]
    # Worst first; assets with nothing applicable evaluated (N/A) go last
    # -- they're not "bad", there's just nothing to rank.
    asset_pct.sort(key=lambda item: (item[1] is None, item[1] if item[1] is not None else 0))
    rows = [["Asset", "% Compliant"]] + [
        [name, "N/A" if pct is None else f"{pct}%"] for name, pct in asset_pct
    ]
    table = Table(rows, colWidths=[4.5 * inch, 2 * inch], repeatRows=1)
    table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
    story.append(table)
    story.append(Spacer(1, 0.3 * inch))

    # Prevalence keyed by control_title (stable across benchmark
    # documents/versions, unlike external_id -- see Check.titles' own
    # docstring in invariant_assessment) -- denominator is "assets where
    # this control was actually evaluated and applicable", never the raw
    # asset count, since a mixed-OS batch won't have every control apply
    # to every asset.
    # Grouping only applicable_pass/applicable_fail (already computed by
    # split_findings, same source of truth Compliance by Asset above uses)
    # -- not a second, independent applicability check -- is what makes
    # this automatically respect both host-only *and* a per-target SSH-
    # absent verdict. Re-deriving applicability here from classify_
    # environment() alone (an earlier version of this function did) missed
    # the SSH case entirely, since that's a per-run signal split_findings
    # already resolved, not a static per-control fact.
    by_title: dict[str, list[Finding]] = defaultdict(list)
    for _, (ap, af, _, _) in per_asset:
        for f in ap + af:
            by_title[f.control_title].append(f)

    prevalence = []
    for title, group in by_title.items():
        affected = [f for f in group if f.status == "FAIL"]
        if affected:
            prevalence.append((title, len(affected), len(group)))
    prevalence.sort(key=lambda item: -item[1])

    if prevalence:
        story.append(Paragraph("Most Prevalent Failures", _styles["Heading2"]))
        rows = [["Control", "Affected"]] + [
            [title, f"{affected} / {applicable} applicable containers"]
            for title, affected, applicable in prevalence[:15]
        ]
        table = Table(rows, colWidths=[4.3 * inch, 2.2 * inch], repeatRows=1)
        table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
        story.append(table)
        story.append(Spacer(1, 0.3 * inch))

    domain_assets: dict[str, set[str]] = defaultdict(set)
    for name, (_, af, _, _) in per_asset:
        for f in af:
            domain_assets[classify_domain(f.control_title)].add(name)
    domain_counts = sorted(domain_assets.items(), key=lambda item: -len(item[1]))

    if domain_counts:
        story.append(Paragraph("Affected Domains", _styles["Heading2"]))
        rows = [["Domain", "Assets Affected"]] + [[d, str(len(names))] for d, names in domain_counts]
        table = Table(rows, colWidths=[4.5 * inch, 2 * inch])
        table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
        story.append(table)
        story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("Next Actions", _styles["Heading2"]))
    story.append(
        Paragraph(
            "Refer to each asset's individual technical report for full evidence and remediation steps.",
            _styles["Normal"],
        )
    )

    doc.build(story)
    return buf.getvalue()


def build_technical_report(
    title: str,
    findings: list[Finding],
    hostname: str | None = None,
    primary_ip: str | None = None,
    container_image: str | None = None,
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"Invariant — {title} — Technical")

    applicable_pass, applicable_fail, not_assessed, not_applicable = split_findings(findings)
    pct = compliance_pct(applicable_pass, applicable_fail)
    pct_text = "N/A" if pct is None else f"{pct}%"

    story = _cover(title, "Technical Report — full findings", findings, hostname, primary_ip, container_image)

    story.append(Paragraph("Assessment Summary", _styles["Heading2"]))
    story.append(
        Paragraph(
            _summary_line(applicable_pass, applicable_fail, not_assessed, not_applicable, len(findings), pct_text),
            _styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.15 * inch))

    domain_rows = [["Domain", "PASS", "FAIL", "N/A"]]
    domains_seen = sorted({classify_domain(f.control_title) for f in findings})
    for domain in domains_seen:
        p = sum(1 for f in applicable_pass if classify_domain(f.control_title) == domain)
        fl = sum(1 for f in applicable_fail if classify_domain(f.control_title) == domain)
        na = sum(1 for f in not_applicable if classify_domain(f.control_title) == domain)
        if p + fl + na == 0:
            continue
        domain_rows.append([domain, str(p), str(fl), str(na)])
    if len(domain_rows) > 1:
        domain_table = Table(domain_rows, colWidths=[3.2 * inch, 1.1 * inch, 1.1 * inch, 1.1 * inch])
        domain_table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
        story.append(domain_table)
    story.append(Spacer(1, 0.3 * inch))

    if applicable_fail:
        story.append(Paragraph(f"Failed Controls ({len(applicable_fail)})", _styles["Heading2"]))
        for domain in sorted({classify_domain(f.control_title) for f in applicable_fail}):
            group = [f for f in applicable_fail if classify_domain(f.control_title) == domain]
            story.append(Paragraph(escape(domain), _styles["Heading3"]))
            story.append(
                Paragraph(escape(DOMAIN_NARRATIVE.get(domain, DOMAIN_NARRATIVE["Other"])), _FINDING_WHY_STYLE)
            )
            for f in _sorted_by_level(group):
                _append_finding_detail(story, f)
        story.append(Spacer(1, 0.2 * inch))

    if not_assessed:
        story.append(Paragraph(f"Not Assessed ({len(not_assessed)})", _styles["Heading2"]))
        story.append(
            Paragraph("Invariant could not determine a PASS/FAIL result for these controls.", _styles["Normal"])
        )
        story.append(_compact_control_table(not_assessed, extra_col="Status"))
        story.append(Spacer(1, 0.2 * inch))

    if not_applicable:
        story.append(Paragraph(f"Not Applicable ({len(not_applicable)})", _styles["Heading2"]))
        story.append(
            Paragraph(
                "These controls do not apply to a containerized environment "
                "(e.g. bootloader, kernel modules, host-level firewall/cron/time "
                "synchronization) and are excluded from the compliance percentage above.",
                _styles["Normal"],
            )
        )
        story.append(_not_applicable_table(not_applicable))
        story.append(Spacer(1, 0.2 * inch))

    if applicable_pass:
        story.append(Paragraph(f"Passed Controls ({len(applicable_pass)})", _styles["Heading2"]))
        story.append(_compact_control_table(applicable_pass))

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Assessment Metadata", _styles["Heading2"]))
    if findings:
        first = findings[0]
        story.append(
            Paragraph(
                f"Benchmark: {escape(first.source_name)}/{escape(first.document_name)} v{escape(first.document_version)}",
                _styles["Normal"],
            )
        )
    story.append(Paragraph(f"Total controls: {len(findings)}", _styles["Normal"]))

    doc.build(story)
    return buf.getvalue()
