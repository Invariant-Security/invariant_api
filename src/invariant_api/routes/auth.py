"""Bootstrap de admin único pro modo appliance: sem admin cadastrado,
GET /auth/status diz has_admin=false e a UI mostra o wizard de setup em
vez de login (ver invariant_frontend). POST /auth/setup só funciona uma
vez -- depois disso vira 409, e o fluxo normal é /auth/login.
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from invariant_api.auth import (
    clear_session_cookie,
    hash_password,
    require_admin_session,
    set_session_cookie,
    verify_password,
)
from invariant_api.storage import postgres as db

router = APIRouter(prefix="/auth")


class AdminCredentials(BaseModel):
    username: str
    password: str


@router.get("/status")
def status() -> dict:
    conn = db.connect()
    has_admin = db.count_admin_users(conn) > 0
    conn.close()
    return {"has_admin": has_admin}


@router.post("/setup")
def setup(credentials: AdminCredentials, response: Response) -> dict:
    conn = db.connect()
    if db.count_admin_users(conn) > 0:
        conn.close()
        raise HTTPException(409, "an admin user already exists")
    db.insert_admin_user(conn, username=credentials.username, password_hash=hash_password(credentials.password))
    conn.commit()
    conn.close()
    set_session_cookie(response, credentials.username)
    return {"username": credentials.username}


@router.post("/login")
def login(credentials: AdminCredentials, response: Response) -> dict:
    conn = db.connect()
    user = db.select_admin_user_by_username(conn, username=credentials.username)
    conn.close()
    if user is None or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(401, "invalid username or password")
    set_session_cookie(response, user["username"])
    return {"username": user["username"]}


@router.post("/logout")
def logout(response: Response) -> dict:
    clear_session_cookie(response)
    return {"status": "ok"}


@router.get("/me")
def me(username: str = Depends(require_admin_session)) -> dict:
    return {"username": username}
