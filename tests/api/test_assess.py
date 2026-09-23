"""POST /assess/{target} -- docker-exec assessment. Mocks assessment_client
and db.select_control_by_title entirely, same pattern test_endpoints.py
uses for the SSH-based /endpoints/{id}/assess.

Now guarded by require_admin_session -- that dependency only checks the
cookie's HMAC signature, no Postgres involved (see auth.py), so tests
set a real cookie via create_session_cookie() directly instead of going
through the DB-backed /auth/setup + /auth/login flow (which would
conflict with this file's fully-mocked db.connect()).
"""

from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.auth import create_session_cookie
from invariant_api.clients import assessment_client
from invariant_api.storage import postgres as db

client = TestClient(main.app)
client.cookies.set("invariant_session", create_session_cookie("admin"))

_FAKE_CONTROL = {
    "external_id": "5.1.20",
    "title": "Ensure sshd PermitRootLogin is disabled",
    "source_name": "CIS",
    "document_name": "debian_linux_12",
    "publisher_version": "2.0.0",
    "normalized_data": {"remediation": "Set PermitRootLogin to no.", "applicability": [{"level": 1}], "scored": True},
    "raw_artifact_path": "raw/debian12.json",
    "content_hash": "deadbeef",
    "retrieved_at": None,
}

_FAKE_RUN = {
    "document": "debian_linux_12",
    "results": [
        {
            "titles": ["Ensure sshd PermitRootLogin is disabled"],
            "status": "FAIL",
            "evidence": "PermitRootLogin yes",
        }
    ],
}


class _DummyConn:
    """db.connect() returns a real psycopg connection normally -- this
    test never touches real Postgres (select_control_by_title is fully
    mocked below), so a bare object with a no-op close() is enough to
    satisfy _findings_from_run()'s conn.close() call.
    """

    def close(self):
        pass


def test_assess_sets_docker_container_target_type(monkeypatch):
    monkeypatch.setattr(assessment_client, "run_assessment", lambda target: _FAKE_RUN)
    monkeypatch.setattr(db, "connect", lambda: _DummyConn())
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: _FAKE_CONTROL)

    response = client.post("/assess/tamois")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["target_type"] == "docker_container"


def test_assess_requires_admin_session():
    anonymous = TestClient(main.app)

    response = anonymous.post("/assess/tamois")

    assert response.status_code == 401
