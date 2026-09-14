"""Unit coverage for reports.py -- no Postgres/HTTP, just Finding objects
in, PDF bytes out. Uses pypdf (dev-only dependency, never ships in the
production image) to extract text and assert on report content -- e.g.
that the CEO report never leaks raw evidence/remediation text.
"""

import io

import pytest
from invariant_contracts import Finding
from pypdf import PdfReader

from invariant_api.reports import (
    ConsolidatedAsset,
    _bar_fill_width,
    build_ceo_report,
    build_consolidated_report,
    build_technical_report,
    split_findings,
)


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


def test_ssh_control_becomes_not_applicable_when_sshd_confirmed_absent():
    # (debian_linux_12, 5.1.20) is a real SSHD_DEPENDENT_CONTROLS entry
    # (PermitRootLogin) -- the default external_id/document_name of the
    # _finding() fixture already matches it.
    findings = [_finding(status="FAIL", evidence_output="sshd_config: PermitRootLogin <sshd-not-installed>")]

    _, applicable_fail, _, not_applicable = split_findings(findings)

    assert applicable_fail == []
    assert not_applicable == findings


def test_ssh_control_stays_applicable_when_sshd_state_is_unknown():
    # UNKNOWN must never hide findings -- only a confirmed ABSENT does.
    findings = [_finding(status="FAIL", evidence_output="sshd_config: PermitRootLogin <sshd-status-unknown>")]

    _, applicable_fail, _, not_applicable = split_findings(findings)

    assert applicable_fail == findings
    assert not_applicable == []


def test_ssh_control_stays_applicable_when_sshd_is_present():
    findings = [_finding(status="FAIL", evidence_output="sshd_config: PermitRootLogin yes")]

    _, applicable_fail, _, not_applicable = split_findings(findings)

    assert applicable_fail == findings
    assert not_applicable == []


def test_host_only_and_ssh_dependent_conditions_never_conflict(monkeypatch):
    # A control that happened to be in both maps (shouldn't exist by
    # design, but the bucketing must not break if it did) -- the two
    # conditions are an `or`, so either one alone is sufficient.
    import invariant_api.finding_taxonomy as taxonomy

    monkeypatch.setattr(taxonomy, "HOST_ONLY_CONTROLS", {("debian_linux_12", "5.1.20")})
    findings = [_finding(status="FAIL", evidence_output="sshd_config: PermitRootLogin yes")]  # sshd present

    _, _, _, not_applicable = split_findings(findings)

    assert not_applicable == findings  # host-only alone is enough


@pytest.mark.parametrize(
    ("pct", "total_width", "expected"),
    [(0, 100, 0), (50, 100, 50), (100, 100, 100), (None, 100, 0)],
)
def test_bar_fill_width_is_proportional(pct, total_width, expected):
    assert _bar_fill_width(pct, total_width) == expected


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


def test_consolidated_prevalence_excludes_ssh_findings_when_sshd_absent():
    # Regression: an earlier version of this function re-derived
    # applicability from classify_environment() alone instead of reusing
    # split_findings, which missed the per-run SSH-absent case entirely --
    # caught live against a real 4-container batch where every container
    # showed sshd absent, yet "Ensure sshd PermitRootLogin is disabled"
    # still appeared as a 4/4 prevalent failure.
    findings = [_finding(status="FAIL", evidence_output="sshd_config: PermitRootLogin <sshd-not-installed>")]
    assets = [_asset("asset-a", findings), _asset("asset-b", findings)]

    text = _extract_text(build_consolidated_report(assets))

    assert "PermitRootLogin" not in text


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


def test_consolidated_processed_applicable_not_applicable_close_mathematically(monkeypatch):
    import invariant_api.finding_taxonomy as taxonomy

    monkeypatch.setattr(taxonomy, "HOST_ONLY_CONTROLS", {("debian_linux_12", "1.4.1")})
    assets = [
        _asset(
            "asset-a",
            [
                _finding(external_id="5.1.20", status="PASS"),
                _finding(external_id="1.4.1", status="FAIL", control_title="Ensure bootloader password is set"),
                _finding(external_id="9.9.9", status="NOT ASSESSED", control_title="Something unresolved"),
            ],
        ),
        _asset("asset-b", [_finding(external_id="5.1.20", status="FAIL")]),
    ]

    text = _extract_text(build_consolidated_report(assets))

    assert "Controls processed: 4" in text
    assert "Applicable controls: 2" in text  # asset-a's PASS + asset-b's FAIL; bootloader and NOT ASSESSED excluded
    assert "Not Applicable: 1" in text
    assert "Not Assessed: 1" in text


def test_not_applicable_table_shows_effective_status_na_and_preserves_raw_result(monkeypatch):
    import invariant_api.finding_taxonomy as taxonomy

    monkeypatch.setattr(taxonomy, "HOST_ONLY_CONTROLS", {("debian_linux_12", "1.4.1"), ("debian_linux_12", "1.4.2")})
    findings = [
        _finding(external_id="1.4.1", status="PASS", control_title="Ensure bootloader password is set"),
        _finding(external_id="1.4.2", status="FAIL", control_title="Ensure access to bootloader config is configured"),
    ]

    text = _extract_text(build_technical_report("tamois", findings))

    assert "Effective Status" in text
    assert "Raw Result" in text
    # Both rows show the literal N/A for Effective Status, but keep their
    # real, different raw results -- collapsing them would make a PASS
    # indistinguishable from a FAIL in this section.
    assert text.count("N/A") >= 2
    assert "PASS" in text
    assert "FAIL" in text


def test_classify_domain_no_longer_leaves_the_previously_other_titles_in_other():
    # Regression: these 3 real tamois FAILs were classified "Other" before
    # the Account & Session Management domain was added.
    from invariant_api.finding_taxonomy import classify_domain

    for title in (
        "Ensure default user umask is configured",
        "Ensure accounts without a valid login shell are locked",
        "Ensure local interactive user home directories are configured",
    ):
        assert classify_domain(title) != "Other"


def test_why_it_matters_appears_once_per_domain_not_once_per_finding():
    findings = [
        _finding(external_id="5.1.20", status="FAIL", control_title="Ensure sshd PermitRootLogin is disabled"),
        _finding(external_id="5.1.21", status="FAIL", control_title="Ensure sshd PermitUserEnvironment is disabled"),
        _finding(external_id="5.1.11", status="FAIL", control_title="Ensure sshd IgnoreRhosts is enabled"),
    ]

    text = _extract_text(build_technical_report("tamois", findings))

    narrative = "Multiple SSH security controls are not explicitly configured."
    assert text.count(narrative) == 1
