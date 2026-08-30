"""Newsletter signup for the "subscribe to updates" form on Home.jsx.

Storage only -- no email/messaging provider is wired up yet, that comes
once one is contracted. Mirrors the billing.py route pattern (plain
function-based route, db.connect()/commit()/close() per request).
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from invariant_api.storage import postgres as db

router = APIRouter()


class SubscribeRequest(BaseModel):
    email: str


class SubscribeResponse(BaseModel):
    status: str


@router.post("/newsletter/subscribe", response_model=SubscribeResponse)
def subscribe(payload: SubscribeRequest) -> SubscribeResponse:
    email = payload.email.strip()
    if not email or "@" not in email:
        raise HTTPException(422, "invalid email")

    conn = db.connect()
    db.insert_newsletter_subscriber(conn, email=email)
    conn.commit()
    conn.close()

    # Always reports success, whether this was a new row or an existing
    # subscriber -- never leak "this email is already subscribed".
    return SubscribeResponse(status="subscribed")
