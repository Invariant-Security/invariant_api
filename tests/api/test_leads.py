"""POST /leads -- hits a real Postgres (DATABASE_URL), same discipline as
test_endpoints.py. slack_client.notify_lead is monkeypatched (Slack itself
is exercised by slack_client's own unit coverage, not here) -- never mock
httpx directly.
"""

import psycopg
import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.routes import leads
from invariant_api.storage import postgres as db

pytestmark = pytest.mark.integration

client = TestClient(main.app)

VALID_PAYLOAD = {
    "name": "Ana Souza",
    "email": "ana@example.com",
    "company": "Exemplo LTDA",
    "role": "CTO",
    "target_scope": "linux",
    "environment_size": "11_50",
    "primary_need": "compliance_cis",
    "message": "Queremos avaliar conformidade CIS no nosso parque Linux.",
}


@pytest.fixture(autouse=True)
def clean_tables():
    try:
        conn = db.connect()
    except (KeyError, psycopg.OperationalError) as exc:
        pytest.skip(f"no reachable DATABASE_URL configured: {exc}")
    with conn.cursor() as cur:
        cur.execute("DELETE FROM leads")
    conn.commit()
    yield
    with conn.cursor() as cur:
        cur.execute("DELETE FROM leads")
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def clean_rate_limit():
    leads._rate_limit_state.clear()
    yield
    leads._rate_limit_state.clear()


def _count_leads() -> int:
    conn = db.connect()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM leads")
        (count,) = cur.fetchone()
    conn.close()
    return count


def _fetch_last_lead() -> dict:
    conn = db.connect()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT name, email, company, slack_notified_at, slack_notify_attempts, slack_last_error "
            "FROM leads ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()
        columns = [desc[0] for desc in cur.description]
    conn.close()
    return dict(zip(columns, row))


def test_valid_lead_is_persisted(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 0, None))

    response = client.post("/leads", json=VALID_PAYLOAD)

    assert response.status_code == 200
    assert response.json() == {"status": "received"}
    assert _count_leads() == 1
    stored = _fetch_last_lead()
    assert stored["email"] == "ana@example.com"


def test_invalid_email_rejected(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 0, None))

    response = client.post("/leads", json={**VALID_PAYLOAD, "email": "not-an-email"})

    assert response.status_code == 422
    assert _count_leads() == 0


def test_missing_name_rejected(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 0, None))

    response = client.post("/leads", json={**VALID_PAYLOAD, "name": ""})

    assert response.status_code == 422
    assert _count_leads() == 0


def test_missing_company_rejected(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 0, None))

    response = client.post("/leads", json={**VALID_PAYLOAD, "company": ""})

    assert response.status_code == 422
    assert _count_leads() == 0


def test_missing_target_scope_rejected(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 0, None))

    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "target_scope"}
    response = client.post("/leads", json=payload)

    assert response.status_code == 422
    assert _count_leads() == 0


def test_message_over_limit_rejected(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 0, None))

    response = client.post("/leads", json={**VALID_PAYLOAD, "message": "x" * 2001})

    assert response.status_code == 422
    assert _count_leads() == 0


def test_honeypot_filled_pretends_success_without_persisting(monkeypatch):
    called = False

    def fake_notify(**kw):
        nonlocal called
        called = True
        return False, 0, None

    monkeypatch.setattr(leads.slack_client, "notify_lead", fake_notify)

    response = client.post("/leads", json={**VALID_PAYLOAD, "website": "http://spam.example"})

    assert response.status_code == 200
    assert response.json() == {"status": "received"}
    assert _count_leads() == 0
    assert called is False


def test_slack_success_records_notified_at(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (True, 1, None))

    response = client.post("/leads", json=VALID_PAYLOAD)

    assert response.status_code == 200
    stored = _fetch_last_lead()
    assert stored["slack_notified_at"] is not None
    assert stored["slack_notify_attempts"] == 1
    assert stored["slack_last_error"] is None


def test_slack_failure_keeps_lead_saved_and_still_returns_200(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 3, "timeout"))

    response = client.post("/leads", json=VALID_PAYLOAD)

    assert response.status_code == 200
    assert _count_leads() == 1
    stored = _fetch_last_lead()
    assert stored["slack_notified_at"] is None
    assert stored["slack_notify_attempts"] == 3
    assert stored["slack_last_error"] == "timeout"


def test_slack_webhook_absent_does_not_error(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 0, None))

    response = client.post("/leads", json=VALID_PAYLOAD)

    assert response.status_code == 200
    stored = _fetch_last_lead()
    assert stored["slack_notified_at"] is None
    assert stored["slack_notify_attempts"] == 0
    assert stored["slack_last_error"] is None


def test_rate_limit_blocks_sixth_request_from_same_ip(monkeypatch):
    monkeypatch.setattr(leads.slack_client, "notify_lead", lambda **kw: (False, 0, None))
    headers = {"X-Real-IP": "203.0.113.7"}

    for _ in range(5):
        response = client.post("/leads", json=VALID_PAYLOAD, headers=headers)
        assert response.status_code == 200

    blocked = client.post("/leads", json=VALID_PAYLOAD, headers=headers)
    assert blocked.status_code == 429


def test_slack_last_error_never_leaks_webhook_url_or_raw_exception(monkeypatch):
    def fake_notify(**kw):
        raise RuntimeError("boom while POSTing to https://hooks.slack.com/services/SECRET/PATH")

    monkeypatch.setattr(leads.slack_client, "notify_lead", fake_notify)

    response = client.post("/leads", json=VALID_PAYLOAD)

    assert response.status_code == 200
    stored = _fetch_last_lead()
    assert stored["slack_last_error"] in ("error", "timeout") or (
        stored["slack_last_error"] is not None and stored["slack_last_error"].startswith("http_")
    )
    assert "hooks.slack.com" not in (stored["slack_last_error"] or "")
    assert "boom" not in (stored["slack_last_error"] or "")
