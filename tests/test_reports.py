"""Unit coverage for reports.py -- no Postgres/HTTP, just Finding objects
in, PDF bytes out. Uses pypdf (dev-only dependency, never ships in the
production image) to extract text and assert on report content -- e.g.
that the CEO report never leaks raw evidence/remediation text.
"""

import io

import pytest
from invariant_contracts import Finding
from pypdf import PdfReader

from invariant_api.reports import ConsolidatedAsset, build_ceo_report, build_consolidated_report, build_technical_report


def _finding(**overrides) -> Finding:
    defaults = dict(
        target="tamois",
        external_id="5.1.20",
        status="FAIL",
        control_title="Ensure sshd PermitRootLogin is disabled",
        source_name="cis",
        document_name="debian_linux_12",
        document_version="2.0.0",
        evidence_output="sshd_config: PermitRootLogin <not set>",
        collected_at="2026-09-13T00:00:00+00:00",
        remediation="Set PermitRootLogin to no in sshd_config.",
        level=1,
        scored=True,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _extract_text(pdf_bytes: bytes) -> str:
    # Newlines collapsed to spaces -- reportlab word-wraps long cell text
    # across lines, so a substring assertion needs to survive an arbitrary
    # wrap point, not just an exact multi-word phrase.
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = " ".join(page.extract_text() for page in reader.pages)
    return " ".join(text.split())


@pytest.mark.parametrize("builder", [build_ceo_report, build_technical_report])
def test_produces_a_valid_pdf(builder):
    pdf_bytes = builder("tamois", [_finding()])

    assert pdf_bytes.startswith(b"%PDF-")


@pytest.mark.parametrize("builder", [build_ceo_report, build_technical_report])
def test_handles_empty_findings_list_without_crashing(builder):
    pdf_bytes = builder("tamois", [])

    assert pdf_bytes.startswith(b"%PDF-")


def test_ceo_report_omits_raw_evidence_remediation_and_control_titles():
    # The CEO report groups failures by domain (narrative), not a list of
    # 57 raw CIS control titles -- neither the evidence/remediation text
    # nor the individual control title should appear; the domain name
    # should, as that's the whole point of the "Key Risks" section.
    text = _extract_text(build_ceo_report("tamois", [_finding()]))

    assert "PermitRootLogin <not set>" not in text
    assert "Set PermitRootLogin to no" not in text
    assert "Ensure sshd PermitRootLogin is disabled" not in text
    assert "SSH Hardening" in text


def test_technical_report_includes_evidence_and_remediation():
    text = _extract_text(build_technical_report("tamois", [_finding()]))

    assert "PermitRootLogin <not set>" in text
    assert "Set PermitRootLogin to no" in text


def test_ceo_report_summarizes_pass_fail_counts():
    findings = [_finding(external_id="1", status="PASS", level=1), _finding(external_id="2", status="FAIL", level=1)]

    text = _extract_text(build_ceo_report("tamois", findings))

    assert "2 controls evaluated" in text
    assert "50% compliant" in text


def test_ceo_report_does_not_misrepresent_totals_with_a_third_status():
    # Defensive: nothing in the pipeline produces a status other than
    # PASS/FAIL today, but the counting must not assume that -- a finding
    # with e.g. "NOT ASSESSED" must show up explicitly, not get silently
    # dropped from both the pass and fail buckets.
    findings = [
        _finding(external_id="1", status="PASS", level=1),
        _finding(external_id="2", status="FAIL", level=1),
        _finding(external_id="3", status="NOT ASSESSED", level=1),
    ]

    text = _extract_text(build_ceo_report("tamois", findings))

    assert "3 controls evaluated" in text
    assert "1 passed" in text
    assert "1 failed" in text
    assert "1 not assessed" in text


def test_technical_report_handles_a_full_size_real_assessment():
    # Regression test: a table-based layout reliably raised
    # reportlab.platypus.doctemplate.LayoutError ("too large") once any
    # single row's remediation text ran long enough to wrap into more
    # lines than fit on one page -- caught live against a real 199-control
    # CIS assessment (tamois, 2026-09-13), where several controls' real
    # remediation text runs past 4000 characters. Short synthetic text
    # (the other tests in this file) never reproduced it: what broke was
    # cell height, not row count.
    long_remediation = "Configure this control as follows. " * 150  # ~5400 chars, matches the worst real case
    findings = [
        _finding(external_id=str(i), status="FAIL" if i % 2 else "PASS", remediation=long_remediation)
        for i in range(199)
    ]

    pdf_bytes = build_technical_report("tamois", findings)

    assert pdf_bytes.startswith(b"%PDF-")


def test_ceo_report_never_recreates_the_cis_level_as_severity_conflation():
    # CIS Level is a benchmark hardening profile, not a severity rating --
    # the report must never say "high-priority"/"critical" tied to a CIS
    # level, only the level itself ("CIS Level 1 failures").
    findings = [_finding(status="FAIL", level=1), _finding(external_id="2", status="FAIL", level=2)]

    text = _extract_text(build_ceo_report("tamois", findings))

    assert "high-priority" not in text.lower()
    assert "critical attention" not in text.lower()
    assert "CIS Level 1 failures" in text
    assert "CIS Level 2 failures" in text


def test_host_only_pass_does_not_inflate_compliance(monkeypatch):
    # Round-1 correction: a host-only control that happens to PASS must
    # not count toward compliance any more than a host-only FAIL would
    # count against it -- both are simply excluded.
    import invariant_api.finding_taxonomy as taxonomy

    monkeypatch.setattr(taxonomy, "HOST_ONLY_CONTROLS", {("debian_linux_12", "1.4.1")})
    findings = [
        _finding(external_id="1.4.1", status="PASS"),  # host-only, would otherwise inflate %
        _finding(external_id="5.1.20", status="FAIL"),  # the only real applicable control
    ]

    text = _extract_text(build_ceo_report("tamois", findings))

    assert "0% compliant" in text  # not 50%: the host-only PASS must not count
    assert "1 not applicable" in text


def test_compliance_is_na_not_0_percent_when_nothing_applicable_was_evaluated(monkeypatch):
    import invariant_api.finding_taxonomy as taxonomy

    monkeypatch.setattr(taxonomy, "HOST_ONLY_CONTROLS", {("debian_linux_12", "1.4.1")})
    findings = [_finding(external_id="1.4.1", status="FAIL")]  # only finding is host-only

    text = _extract_text(build_ceo_report("tamois", findings))

    assert "N/A compliant" in text
    assert "0% compliant" not in text


def test_applicable_third_status_does_not_dilute_compliance_denominator():
    # A container_relevant finding with a non-PASS/FAIL status must not
    # count toward "evaluated" -- the denominator is PASS+FAIL only.
    findings = [
        _finding(external_id="5.1.20", status="PASS"),
        _finding(external_id="5.1.21", status="NOT ASSESSED"),
    ]

    text = _extract_text(build_ceo_report("tamois", findings))

    assert "100% compliant" in text  # 1/1, not 1/2


def test_technical_report_separates_not_assessed_from_not_applicable(monkeypatch):
    import invariant_api.finding_taxonomy as taxonomy

    monkeypatch.setattr(taxonomy, "HOST_ONLY_CONTROLS", {("debian_linux_12", "1.4.1")})
    # Deliberately both host-only AND not-PASS/FAIL -- not_assessed must
    # win the bucketing priority, never counted as not_applicable too.
    findings = [_finding(external_id="1.4.1", status="NOT ASSESSED", control_title="Ensure bootloader password is set")]

    text = _extract_text(build_technical_report("tamois", findings))

    assert "Not Assessed" in text
    assert "Not Applicable" not in text


def _asset(name: str, findings: list[Finding], status: str = "success", error: str | None = None) -> ConsolidatedAsset:
    return ConsolidatedAsset(name=name, status=status, findings=findings, error=error)


def test_consolidated_report_valid_pdf_with_zero_and_one_asset():
    assert build_consolidated_report([]).startswith(b"%PDF-")
    assert build_consolidated_report([_asset("tamois", [_finding()])]).startswith(b"%PDF-")


def test_consolidated_overview_reports_selected_assessed_failed():
    assets = [
        _asset("tamois", [_finding()]),
        _asset("babybet", [], status="error", error="HTTP 502"),
    ]

    text = _extract_text(build_consolidated_report(assets))

    assert "2 selected / 1 assessed / 1 failed" in text
    assert "Failed to assess: babybet" in text


def test_consolidated_prevalence_denominator_is_applicable_assets_not_total_batch():
    # 3 assets in the batch, but one of them (asset-c) never had this
    # control evaluated at all -- the denominator must be 2 (the assets
    # where it was actually applicable), not 3 (the whole batch).
    shared_title = "Ensure sshd PermitRootLogin is disabled"
    assets = [
        _asset("asset-a", [_finding(control_title=shared_title, status="FAIL")]),
        _asset("asset-b", [_finding(control_title=shared_title, status="PASS")]),
        _asset("asset-c", [_finding(control_title="Some other control", status="PASS")]),
    ]

    text = _extract_text(build_consolidated_report(assets))

    assert "1 / 2 applicable containers" in text
    assert "1 / 3" not in text


def test_consolidated_prevalence_excludes_host_only_findings(monkeypatch):
    import invariant_api.finding_taxonomy as taxonomy

    monkeypatch.setattr(taxonomy, "HOST_ONLY_CONTROLS", {("debian_linux_12", "1.4.1")})
    assets = [
        _asset("asset-a", [_finding(external_id="1.4.1", status="FAIL", control_title="Ensure bootloader password is set")]),
        _asset("asset-b", [_finding(external_id="1.4.1", status="FAIL", control_title="Ensure bootloader password is set")]),
    ]

    text = _extract_text(build_consolidated_report(assets))

    assert "bootloader" not in text.lower()  # host-only, never counted as a prevalent failure


def test_consolidated_domain_names_are_not_double_escaped():
    # Regression: plain Table cells (unlike Paragraph) never parse markup,
    # so xml.sax.saxutils.escape()'ing a domain name like "Authentication
    # & PAM" before putting it in a Table row left a literal "&amp;" on
    # the page -- caught visually against a real 4-container batch.
    findings = [_finding(control_title="Ensure pam_faillock module is enabled", status="FAIL")]
    text = _extract_text(build_consolidated_report([_asset("tamois", findings)]))

    assert "Authentication & PAM" in text
    assert "&amp;" not in text


def test_consolidated_compliance_by_asset_uses_the_same_evaluated_formula():
    assets = [
        _asset("good", [_finding(external_id="1", status="PASS"), _finding(external_id="2", status="FAIL")]),
        _asset("bad", [_finding(external_id="1", status="FAIL")]),
    ]

    text = _extract_text(build_consolidated_report(assets))

    assert "50%" in text  # good: 1 pass / 2 evaluated
    assert "0%" in text  # bad: 0 pass / 1 evaluated
