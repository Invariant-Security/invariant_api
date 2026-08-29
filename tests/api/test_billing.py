"""Mocks mercadopago.SDK and invariant_api.storage.postgres entirely --
same discipline as tests/api/test_api.py mocking STATUS_PATH/RUNS_PATH
instead of touching a real filesystem. No real Postgres or Mercado Pago
credentials needed to run these.
"""

import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.routes import billing

client = TestClient(main.app)


class FakeConn:
    def commit(self):
        pass

    def close(self):
        pass


@pytest.fixture(autouse=True)
def fake_db(monkeypatch):
    monkeypatch.setattr(billing.db, "connect", lambda: FakeConn())
    monkeypatch.setattr(billing.db, "insert_contract", lambda conn, **kwargs: 42)
    monkeypatch.setattr(billing.db, "update_contract_mp_payment_id", lambda conn, **kwargs: None)


@pytest.fixture
def fake_mercadopago(monkeypatch):
    class FakePayment:
        def create(self, payload):
            self.last_payload = payload
            return {
                "status": 201,
                "response": {
                    "id": 999,
                    "status": "pending",
                    "point_of_interaction": {
                        "transaction_data": {"qr_code": "00020126...pix", "qr_code_base64": "aGVsbG8="}
                    },
                },
            }

    class FakeSDK:
        def __init__(self, access_token):
            self.access_token = access_token
            self.payment_client = FakePayment()

        def payment(self):
            return self.payment_client

    monkeypatch.setenv("MERCADO_PAGO_ACCESS_TOKEN", "TEST-token")
    monkeypatch.setattr(billing, "mercadopago", type("m", (), {"SDK": FakeSDK}))
    return FakeSDK


def test_checkout_single_plan_computes_price_server_side(fake_mercadopago):
    response = client.post(
        "/billing/checkout",
        json={"plan": "single", "activations": 2, "contact_name": "Ana", "contact_email": "ana@example.com"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["amount_cents"] == 2_400_000  # 2 x R$ 12.000,00
    assert body["qr_code"] == "00020126...pix"


def test_checkout_multi_plan_charges_base_plus_extra_activations(fake_mercadopago):
    response = client.post(
        "/billing/checkout",
        json={"plan": "multi", "activations": 5, "contact_name": "Ana", "contact_email": "ana@example.com"},
    )

    assert response.status_code == 200
    # base (3 ativações, R$30.000) + 2 extras a R$8.000 = R$46.000
    assert response.json()["amount_cents"] == 4_600_000


def test_checkout_rejects_unknown_plan(fake_mercadopago):
    response = client.post(
        "/billing/checkout",
        json={"plan": "enterprise", "activations": 1, "contact_name": "Ana", "contact_email": "ana@example.com"},
    )
    assert response.status_code == 422


def test_checkout_without_credentials_returns_503(monkeypatch):
    monkeypatch.delenv("MERCADO_PAGO_ACCESS_TOKEN", raising=False)
    response = client.post(
        "/billing/checkout",
        json={"plan": "single", "activations": 1, "contact_name": "Ana", "contact_email": "ana@example.com"},
    )
    assert response.status_code == 503


def test_webhook_rejects_missing_signature():
    response = client.post("/webhook/mercadopago", json={"data": {"id": "999"}})
    assert response.status_code == 401


def test_webhook_rejects_invalid_signature(monkeypatch):
    monkeypatch.setenv("MERCADO_PAGO_WEBHOOK_SECRET", "shh")
    response = client.post(
        "/webhook/mercadopago",
        json={"data": {"id": "999"}},
        headers={"x-signature": "ts=1,v1=deadbeef", "x-request-id": "req-1"},
    )
    assert response.status_code == 401


def test_webhook_confirms_paid_contract_on_valid_signature(monkeypatch):
    monkeypatch.setenv("MERCADO_PAGO_WEBHOOK_SECRET", "shh")
    monkeypatch.setenv("MERCADO_PAGO_ACCESS_TOKEN", "TEST-token")

    class FakePayment:
        def get(self, payment_id):
            return {"response": {"status": "approved", "external_reference": "contract:42"}}

    class FakeSDK:
        def __init__(self, access_token):
            pass

        def payment(self):
            return FakePayment()

    monkeypatch.setattr(billing, "mercadopago", type("m", (), {"SDK": FakeSDK}))
    monkeypatch.setattr(billing.db, "update_contract_paid", lambda conn, id: True)

    data_id, ts = "999", "123"
    manifest = f"id:{data_id};request-id:req-1;ts:{ts};"
    v1 = hmac.new(b"shh", manifest.encode(), hashlib.sha256).hexdigest()

    response = client.post(
        "/webhook/mercadopago",
        json={"data": {"id": data_id}},
        headers={"x-signature": f"ts={ts},v1={v1}", "x-request-id": "req-1"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "confirmed"


def test_webhook_ignores_non_contract_reference(monkeypatch):
    monkeypatch.setenv("MERCADO_PAGO_WEBHOOK_SECRET", "shh")
    monkeypatch.setenv("MERCADO_PAGO_ACCESS_TOKEN", "TEST-token")

    class FakePayment:
        def get(self, payment_id):
            return {"response": {"status": "approved", "external_reference": "aposta:1"}}

    class FakeSDK:
        def __init__(self, access_token):
            pass

        def payment(self):
            return FakePayment()

    monkeypatch.setattr(billing, "mercadopago", type("m", (), {"SDK": FakeSDK}))

    data_id, ts = "999", "123"
    manifest = f"id:{data_id};request-id:req-1;ts:{ts};"
    v1 = hmac.new(b"shh", manifest.encode(), hashlib.sha256).hexdigest()

    response = client.post(
        "/webhook/mercadopago",
        json={"data": {"id": data_id}},
        headers={"x-signature": f"ts={ts},v1={v1}", "x-request-id": "req-1"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
