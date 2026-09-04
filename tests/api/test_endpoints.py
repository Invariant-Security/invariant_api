"""CRUD de /endpoints + gatilho de discovery -- hits a real Postgres
(DATABASE_URL) same as tests/storage/test_postgres.py. discovery_client is
monkeypatched (invariant_discovery is a separate service/repo, not
exercised here -- see invariant_discovery's own tests for the scanning
logic itself).
"""

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.clients import assessment_client, discovery_client
from invariant_api.storage import postgres as db

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def clean_tables():
    try:
        conn = db.connect()
    except (KeyError, psycopg.OperationalError) as exc:
        pytest.skip(f"no reachable DATABASE_URL configured: {exc}")
    with conn.cursor() as cur:
        cur.execute("DELETE FROM discovery_results")
        cur.execute("DELETE FROM endpoints")
        cur.execute("DELETE FROM admin_users")
    conn.commit()
    yield
    with conn.cursor() as cur:
        cur.execute("DELETE FROM discovery_results")
        cur.execute("DELETE FROM endpoints")
        cur.execute("DELETE FROM admin_users")
    conn.commit()
    conn.close()


@pytest.fixture
def session_client():
    """A logged-in TestClient -- every /endpoints route requires an admin
    session (routes/endpoints.py's `dependencies=[Depends(require_admin_session)]`).
    """
    c = TestClient(main.app)
    c.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})
    return c


def test_endpoints_require_auth():
    anonymous = TestClient(main.app)

    response = anonymous.get("/endpoints")

    assert response.status_code == 401


def test_create_endpoint_rejects_invalid_address(session_client):
    response = session_client.post("/endpoints", json={"address": "not-an-ip"})

    assert response.status_code == 422


def test_create_and_list_single_ip_endpoint(session_client):
    create = session_client.post("/endpoints", json={"address": "10.0.0.5", "label": "gateway"})
    assert create.status_code == 200

    listed = session_client.get("/endpoints").json()

    assert len(listed) == 1
    assert listed[0]["address"] == "10.0.0.5"
    assert listed[0]["label"] == "gateway"
    assert listed[0]["classification"] is None  # nenhuma discovery rodou ainda


def test_create_cidr_range_endpoint(session_client):
    response = session_client.post("/endpoints", json={"address": "10.0.0.0/24", "tags": ["filial-sp"]})

    assert response.status_code == 200
    assert response.json()["address"] == "10.0.0.0/24"


def test_delete_endpoint(session_client):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]

    delete = session_client.delete(f"/endpoints/{endpoint_id}")
    assert delete.status_code == 200

    assert session_client.get("/endpoints").json() == []


def test_delete_missing_endpoint_returns_404(session_client):
    response = session_client.delete("/endpoints/999999")

    assert response.status_code == 404


def test_discover_persists_results_and_they_show_in_list(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5", "label": "gateway"}).json()["id"]

    fake_result = {
        "ip": "10.0.0.5",
        "classification": "linux",
        "confidence": 0.82,
        "evidence": {"open_ports": [22], "banners": {"22": "SSH-2.0-OpenSSH_9.2 Debian"}},
        "scanned_at": "2026-09-02T00:00:00+00:00",
    }
    monkeypatch.setattr(discovery_client, "discover", lambda addresses: [fake_result])

    response = session_client.post(f"/endpoints/{endpoint_id}/discover")

    assert response.status_code == 200
    assert response.json() == [fake_result]

    listed = session_client.get("/endpoints").json()
    assert listed[0]["classification"] == "linux"
    assert listed[0]["confidence"] == pytest.approx(0.82)

    # scanned_at round-trips through a TIMESTAMPTZ column -- Postgres/psycopg
    # preserve the instant, not the exact "+00:00" vs "Z" spelling (confirmed:
    # comes back "...00:00:00Z" here even though "+00:00" was sent in), so
    # compare everything except that field exactly and parse scanned_at.
    results = session_client.get(f"/endpoints/{endpoint_id}/results").json()
    assert len(results) == 1
    result = results[0]
    assert {k: v for k, v in result.items() if k != "scanned_at"} == {
        k: v for k, v in fake_result.items() if k != "scanned_at"
    }
    assert result["scanned_at"].replace("Z", "+00:00") == fake_result["scanned_at"]


def test_discover_missing_endpoint_returns_404(session_client):
    response = session_client.post("/endpoints/999999/discover")

    assert response.status_code == 404


def test_discover_propagates_discovery_service_failure_as_502(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]

    def boom(addresses):
        raise ConnectionError("invariant_discovery unreachable")

    monkeypatch.setattr(discovery_client, "discover", boom)

    response = session_client.post(f"/endpoints/{endpoint_id}/discover")

    assert response.status_code == 502


# --- POST /endpoints/{id}/assess (SSH-based remote assessment) ---
#
# _findings_from_run() joins each invariant_assessment result against
# Postgres control metadata (db.select_control_by_title, called from
# invariant_api.routes.assess) -- monkeypatched here the same way
# discovery_client is monkeypatched above, since invariant_assessment
# itself is a separate service/repo not exercised by this suite.

_FAKE_DISCOVERY_RESULT = {
    "ip": "10.0.0.5",
    "classification": "linux",
    "confidence": 0.91,
    "evidence": {"open_ports": [22], "banners": {"22": "SSH-2.0-OpenSSH_9.2 Debian"}},
    "scanned_at": "2026-09-02T00:00:00+00:00",
}

_FAKE_CONTROL = {
    "external_id": "1.1.1",
    "title": "Ensure SSH PermitRootLogin is disabled",
    "source_name": "CIS",
    "document_name": "CIS Debian Linux 12 Benchmark",
    "publisher_version": "1.0.0",
    "normalized_data": {"remediation": "Set PermitRootLogin to no.", "applicability": [{"level": 1}], "scored": True},
    "raw_artifact_path": "raw/debian12.json",
    "content_hash": "deadbeef",
    "retrieved_at": None,
}

_FAKE_RUN = {
    "document": "debian_linux_12",
    "results": [
        {
            "titles": ["Ensure SSH PermitRootLogin is disabled"],
            "status": "FAIL",
            "evidence": "PermitRootLogin yes",
        }
    ],
}


def _discover_endpoint(session_client, monkeypatch, endpoint_id):
    monkeypatch.setattr(discovery_client, "discover", lambda addresses: [_FAKE_DISCOVERY_RESULT])
    response = session_client.post(f"/endpoints/{endpoint_id}/discover")
    assert response.status_code == 200


def test_assess_discovered_endpoint_requires_discovery_first(session_client):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]

    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 422


def test_assess_discovered_endpoint_calls_assessment_client_with_ip_and_credentials(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    captured = {}

    def fake_run_assessment_remote(**kwargs):
        captured.update(kwargs)
        return _FAKE_RUN

    monkeypatch.setattr(assessment_client, "run_assessment_remote", fake_run_assessment_remote)
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: _FAKE_CONTROL)

    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["control_title"] == "Ensure SSH PermitRootLogin is disabled"
    assert body[0]["status"] == "FAIL"

    assert captured["host"] == "10.0.0.5"
    assert captured["username"] == "root"
    assert captured["auth_method"] == "password"
    assert captured["password"] == "hunter2"


def test_assess_discovered_endpoint_propagates_assessment_service_error(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    def boom(**kwargs):
        request = httpx.Request("POST", "http://assessment:8000/assessment/run-remote")
        response = httpx.Response(401, request=request, text="bad SSH credentials")
        raise httpx.HTTPStatusError("401", request=request, response=response)

    monkeypatch.setattr(assessment_client, "run_assessment_remote", boom)

    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "wrong"},
    )

    assert response.status_code == 401


def test_assess_discovered_endpoint_requires_auth():
    anonymous = TestClient(main.app)

    response = anonymous.post(
        "/endpoints/1/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 401


def _assert_marker_absent_from_table(conn, table, marker):
    """Generic scan: every column of every row in `table`, stringified,
    must not contain `marker`. Doesn't need updating if columns are added
    later -- SELECT * picks them up automatically.
    """
    with conn.cursor() as cur:
        cur.execute(f"SELECT * FROM {table}")
        rows = cur.fetchall()
    for row in rows:
        for value in row:
            assert marker not in str(value), f"found marker in {table}: {value!r}"


def test_submitted_credentials_never_persisted_to_db(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    monkeypatch.setattr(assessment_client, "run_assessment_remote", lambda **kwargs: _FAKE_RUN)
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: _FAKE_CONTROL)

    marker = "SUPER-SECRET-MARKER-XYZ-DO-NOT-LEAK"
    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": marker},
    )
    assert response.status_code == 200

    conn = db.connect()
    _assert_marker_absent_from_table(conn, "endpoints", marker)
    _assert_marker_absent_from_table(conn, "discovery_results", marker)
    conn.close()


def test_submitted_credentials_never_in_response_body(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    monkeypatch.setattr(assessment_client, "run_assessment_remote", lambda **kwargs: _FAKE_RUN)
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: _FAKE_CONTROL)

    marker = "SUPER-SECRET-MARKER-XYZ-DO-NOT-LEAK"
    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": marker},
    )

    assert response.status_code == 200
    assert marker not in response.text
