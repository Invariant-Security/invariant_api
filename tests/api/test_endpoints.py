"""CRUD de /endpoints + gatilho de discovery -- hits a real Postgres
(DATABASE_URL) same as tests/storage/test_postgres.py. discovery_client is
monkeypatched (invariant_discovery is a separate service/repo, not
exercised here -- see invariant_discovery's own tests for the scanning
logic itself).
"""

import psycopg
import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.clients import discovery_client
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
