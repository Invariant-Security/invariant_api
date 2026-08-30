"""Pix checkout for the pricing section on Home.jsx (invariant_frontend).

Mirrors the Mercado Pago integration already running in production for
BabyBet (app/routes_babybet.py + app/routes_webhook.py): the Payment API
directly with payment_method_id="pix" (not a redirect-based Preference/
Checkout Pro), the amount always computed server-side, and the webhook
re-fetching the payment from Mercado Pago's API instead of trusting the
notification body.
"""

import hashlib
import hmac
import os

import mercadopago
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from invariant_api.storage import postgres as db

router = APIRouter()

REFERENCE_PREFIX = "contract:"

_PRICES_CENTS = {
    "single": 1_200_000,  # R$ 12.000,00 / ativação / ano
    "multi_base": 3_000_000,  # R$ 30.000,00 / 3 ativações incluídas / ano
    "multi_extra": 800_000,  # R$ 8.000,00 / ativação adicional além das 3
}


def _compute_amount_cents(plan: str, activations: int) -> int:
    if plan == "single":
        return _PRICES_CENTS["single"] * activations
    if plan == "multi":
        if activations <= 3:
            return _PRICES_CENTS["multi_base"]
        return _PRICES_CENTS["multi_base"] + (activations - 3) * _PRICES_CENTS["multi_extra"]
    raise ValueError(f"unknown plan {plan!r}")


class CheckoutRequest(BaseModel):
    plan: str
    activations: int
    contact_name: str
    contact_email: str


class CheckoutResponse(BaseModel):
    id: int
    qr_code: str
    qr_code_base64: str
    amount_cents: int


@router.post("/billing/checkout", response_model=CheckoutResponse)
def checkout(payload: CheckoutRequest) -> CheckoutResponse:
    if payload.plan not in ("single", "multi"):
        raise HTTPException(422, f"unknown plan {payload.plan!r}")
    if payload.activations <= 0:
        raise HTTPException(422, "activations must be positive")

    amount_cents = _compute_amount_cents(payload.plan, payload.activations)

    conn = db.connect()
    contract_id = db.insert_contract(
        conn,
        plan=payload.plan,
        activations=payload.activations,
        amount_cents=amount_cents,
        contact_name=payload.contact_name,
        contact_email=payload.contact_email,
    )
    conn.commit()

    access_token = os.environ.get("MERCADO_PAGO_ACCESS_TOKEN")
    if not access_token:
        conn.close()
        raise HTTPException(503, "Pagamento indisponível no momento -- tente novamente mais tarde.")

    mp_payload = {
        "transaction_amount": amount_cents / 100,
        "payment_method_id": "pix",
        "description": f"Invariant - {payload.plan} ({payload.activations} ativações)",
        "payer": {"email": payload.contact_email, "first_name": payload.contact_name},
        "external_reference": f"{REFERENCE_PREFIX}{contract_id}",
    }
    base_url = os.environ.get("INVARIANT_API_BASE_URL", "")
    if base_url.startswith("https://"):
        mp_payload["notification_url"] = f"{base_url.rstrip('/')}/webhook/mercadopago"

    sdk = mercadopago.SDK(access_token)
    try:
        response = sdk.payment().create(mp_payload)
    except Exception as e:
        conn.close()
        raise HTTPException(502, "Falha ao criar cobrança Pix.") from e

    body = response.get("response", {})
    if response.get("status", 500) >= 300:
        conn.close()
        raise HTTPException(502, f"Mercado Pago recusou a cobrança: {body}")

    payment_id = body.get("id")
    if payment_id:
        db.update_contract_mp_payment_id(conn, id=contract_id, mp_payment_id=str(payment_id))
        conn.commit()
    conn.close()

    transaction_data = body.get("point_of_interaction", {}).get("transaction_data", {})
    return CheckoutResponse(
        id=contract_id,
        qr_code=transaction_data.get("qr_code", ""),
        qr_code_base64=transaction_data.get("qr_code_base64", ""),
        amount_cents=amount_cents,
    )


@router.get("/billing/status/{contract_id}")
def status(contract_id: int) -> dict:
    conn = db.connect()
    contract = db.select_contract_by_id(conn, id=contract_id)
    conn.close()
    if contract is None:
        raise HTTPException(404, "contract not found")
    return {"id": contract["id"], "status": contract["status"]}


@router.post("/webhook/mercadopago")
async def mercadopago_webhook(request: Request) -> dict:
    x_signature = request.headers.get("x-signature", "")
    x_request_id = request.headers.get("x-request-id", "")
    body = await request.json()
    data_id = str(body.get("data", {}).get("id", ""))

    webhook_secret = os.environ.get("MERCADO_PAGO_WEBHOOK_SECRET")
    parts = dict(p.split("=", 1) for p in x_signature.split(",") if "=" in p)
    ts, v1 = parts.get("ts"), parts.get("v1")
    if not webhook_secret or not ts or not v1 or not data_id:
        raise HTTPException(401)

    manifest = f"id:{data_id};request-id:{x_request_id};ts:{ts};"
    expected = hmac.new(webhook_secret.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, v1):
        raise HTTPException(401)

    # Never trusts the notification body for the payment status -- always
    # re-fetches from Mercado Pago's own API.
    access_token = os.environ.get("MERCADO_PAGO_ACCESS_TOKEN")
    sdk = mercadopago.SDK(access_token)
    payment = sdk.payment().get(data_id)["response"]
    if payment.get("status") != "approved":
        return {"status": "ignored"}

    reference = payment.get("external_reference") or ""
    if not reference.startswith(REFERENCE_PREFIX):
        return {"status": "ignored"}
    id_str = reference[len(REFERENCE_PREFIX):]
    if not id_str.isdigit():
        return {"status": "ignored"}

    conn = db.connect()
    updated = db.update_contract_paid(conn, id=int(id_str))
    conn.commit()
    conn.close()
    return {"status": "confirmed" if updated else "already_confirmed"}
