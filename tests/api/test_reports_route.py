"""No mocking needed -- reports.py's builders are pure functions, so this
exercises the real thing end-to-end through the HTTP layer.
"""

from fastapi.testclient import TestClient

from invariant_api import main

client = TestClient(main.app)

_FINDING = {
    "target": "tamois",
    "external_id": "5.1.20",
    "status": "FAIL",
    "control_title": "Ensure sshd PermitRootLogin is disabled",
    "source_name": "cis",
    "document_name": "debian_linux_12",
    "document_version": "2.0.0",
    "evidence_output": "sshd_config: PermitRootLogin <not set>",
    "collected_at": "2026-09-13T00:00:00+00:00",
    "remediation": "Set PermitRootLogin to no.",
    "level": 1,
    "scored": True,
}


def test_ceo_report_returns_pdf():
    response = client.post("/reports/pdf", json={"title": "tamois", "kind": "ceo", "findings": [_FINDING]})

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert 'filename="invariant-ceo-report.pdf"' in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-")


def test_technical_report_returns_pdf():
    response = client.post("/reports/pdf", json={"title": "tamois", "kind": "technical", "findings": [_FINDING]})

    assert response.status_code == 200
    assert 'filename="invariant-technical-report.pdf"' in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-")


def test_invalid_kind_returns_422():
    response = client.post("/reports/pdf", json={"title": "tamois", "kind": "bogus", "findings": [_FINDING]})

    assert response.status_code == 422


def test_empty_findings_list_still_returns_a_pdf():
    response = client.post("/reports/pdf", json={"title": "tamois", "kind": "ceo", "findings": []})

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")


def test_consolidated_report_returns_pdf():
    response = client.post(
        "/reports/pdf",
        json={
            "title": "Consolidated Assessment",
            "kind": "consolidated",
            "assets": [
                {"name": "tamois", "status": "success", "findings": [_FINDING]},
                {"name": "babybet", "status": "error", "findings": [], "error": "HTTP 502"},
            ],
        },
    )

    assert response.status_code == 200
    assert 'filename="invariant-consolidated-report.pdf"' in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-")


def test_consolidated_report_with_no_assets_still_returns_a_pdf():
    response = client.post("/reports/pdf", json={"title": "Consolidated Assessment", "kind": "consolidated"})

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")
