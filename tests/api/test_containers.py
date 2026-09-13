"""Mocks assessment_client.list_containers entirely -- no real
invariant_assessment service or Docker socket needed to run these.
"""

from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.routes import assess

client = TestClient(main.app)


def test_filters_out_invariants_own_containers(monkeypatch):
    monkeypatch.setattr(
        assess.assessment_client,
        "list_containers",
        lambda: [
            {"name": "invariant-appliance-web-1", "image": "ghcr.io/invariant-security/invariant-web:v1"},
            {"name": "invariant-next-api", "image": "ghcr.io/invariant-security/invariant-api:v1"},
            {"name": "tamois", "image": "tamois-ia-juridica-tamois"},
        ],
    )

    response = client.get("/containers")

    assert response.status_code == 200
    assert response.json() == [{"name": "tamois", "image": "tamois-ia-juridica-tamois"}]


def test_empty_list_returns_empty_array(monkeypatch):
    monkeypatch.setattr(assess.assessment_client, "list_containers", lambda: [])

    response = client.get("/containers")

    assert response.status_code == 200
    assert response.json() == []


def test_check_container_proxies_check_target(monkeypatch):
    monkeypatch.setattr(
        assess.assessment_client,
        "check_target",
        lambda name: {
            "testable": True,
            "os_id": "debian",
            "os_version_id": "12",
            "family": "debian_ubuntu",
            "reason_code": None,
            "reason": None,
        },
    )

    response = client.get("/containers/tamois/check")

    assert response.status_code == 200
    assert response.json()["testable"] is True
    assert response.headers["cache-control"] == "no-store"


def test_check_container_upstream_error_propagates_status(monkeypatch):
    import httpx

    def raise_error(name):
        request = httpx.Request("POST", "http://assessment/assessment/check")
        response = httpx.Response(502, request=request, text="assessment unreachable")
        raise httpx.HTTPStatusError("boom", request=request, response=response)

    monkeypatch.setattr(assess.assessment_client, "check_target", raise_error)

    response = client.get("/containers/tamois/check")

    assert response.status_code == 502
