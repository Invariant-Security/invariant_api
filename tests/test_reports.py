"""Unit coverage for reports.py -- no Postgres/HTTP, just Finding objects
in, PDF bytes out. Uses pypdf (dev-only dependency, never ships in the
production image) to extract text and assert on report content -- e.g.
that the CEO report never leaks raw evidence/remediation text.
"""

import io

import pytest
from invariant_contracts import Finding
from pypdf import PdfReader

from invariant_api.reports import build_ceo_report, build_technical_report


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


def test_ceo_report_omits_raw_evidence_and_remediation():
    text = _extract_text(build_ceo_report("tamois", [_finding()]))

    assert "PermitRootLogin <not set>" not in text
    assert "Set PermitRootLogin to no" not in text
    assert "Ensure sshd PermitRootLogin is disabled" in text  # control title stays


def test_technical_report_includes_evidence_and_remediation():
    text = _extract_text(build_technical_report("tamois", [_finding()]))

    assert "PermitRootLogin <not set>" in text
    assert "Set PermitRootLogin to no" in text


def test_ceo_report_summarizes_pass_fail_counts():
    findings = [_finding(external_id="1", status="PASS", level=1), _finding(external_id="2", status="FAIL", level=1)]

    text = _extract_text(build_ceo_report("tamois", findings))

    assert "2 controls evaluated" in text
    assert "50% compliant" in text


def test_ceo_report_says_no_high_priority_issues_when_none_found():
    findings = [_finding(status="PASS", level=1)]

    text = _extract_text(build_ceo_report("tamois", findings))

    assert "No high-priority" in text
