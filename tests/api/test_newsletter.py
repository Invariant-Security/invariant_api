"""Mocks invariant_api.storage.postgres entirely -- same discipline as
test_billing.py. No real Postgres needed to run these.
"""

import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.routes import newsletter

client = TestClient(main.app)


class FakeConn:
    def commit(self):
        pass

    def close(self):
        pass


@pytest.fixture(autouse=True)
def fake_db(monkeypatch):
    monkeypatch.setattr(newsletter.db, "connect", lambda: FakeConn())
    monkeypatch.setattr(newsletter.db, "insert_newsletter_subscriber", lambda conn, **kwargs: 1)


def test_subscribe_returns_subscribed():
    response = client.post("/newsletter/subscribe", json={"email": "ana@example.com"})

    assert response.status_code == 200
    assert response.json() == {"status": "subscribed"}


def test_subscribe_reports_success_even_on_conflict(monkeypatch):
    # ON CONFLICT DO NOTHING -- insert_newsletter_subscriber returns None,
    # the route must still report success (never leak "already subscribed").
    monkeypatch.setattr(newsletter.db, "insert_newsletter_subscriber", lambda conn, **kwargs: None)

    response = client.post("/newsletter/subscribe", json={"email": "ana@example.com"})

    assert response.status_code == 200
    assert response.json() == {"status": "subscribed"}


def test_subscribe_rejects_empty_email():
    response = client.post("/newsletter/subscribe", json={"email": ""})
    assert response.status_code == 422


def test_subscribe_rejects_email_without_at_sign():
    response = client.post("/newsletter/subscribe", json={"email": "not-an-email"})
    assert response.status_code == 422
