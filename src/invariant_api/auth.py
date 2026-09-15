"""Auth pra um appliance single-admin, não SaaS multi-tenant -- por isso
tudo aqui é stdlib (hashlib/hmac/secrets), sem passlib/bcrypt/argon2/
itsdangerous/python-jose. PBKDF2-SHA256 em contagem de iterações
recomendada pelo NIST é adequado pra um único admin; um cookie assinado a
mão com HMAC cobre sessão sem precisar de dependência nova.
"""

import hashlib
import hmac
import os
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode

from fastapi import HTTPException, Request

from invariant_api.config import load_dotenv

_PBKDF2_ITERATIONS = 310_000
_SESSION_COOKIE_NAME = "invariant_session"
_SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60  # 7 dias


def _secret_key() -> bytes:
    """INVARIANT_API_SECRET_KEY é gerado uma vez pelo postinst do .deb (ver
    plano de empacotamento) -- em dev, cai num valor fixo só pra não
    quebrar `docker compose up` sem .env preenchido; nunca use esse
    fallback em produção (o instalador sempre define a variável real).
    """
    load_dotenv()
    key = os.environ.get("INVARIANT_API_SECRET_KEY")
    if not key:
        key = "dev-only-insecure-secret-key-do-not-use-in-production"
    return key.encode("utf-8")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${urlsafe_b64encode(salt).decode()}${urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = urlsafe_b64decode(salt_b64)
        expected = urlsafe_b64decode(digest_b64)
    except Exception:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    return hmac.compare_digest(candidate, expected)


def create_session_cookie(username: str) -> str:
    payload = urlsafe_b64encode(username.encode("utf-8")).decode()
    signature = hmac.new(_secret_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def verify_session_cookie(cookie_value: str) -> str | None:
    try:
        payload, signature = cookie_value.split(".", 1)
    except ValueError:
        return None
    expected_signature = hmac.new(_secret_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None
    try:
        return urlsafe_b64decode(payload).decode("utf-8")
    except Exception:
        return None


def set_session_cookie(response, username: str) -> None:
    response.set_cookie(
        _SESSION_COOKIE_NAME,
        create_session_cookie(username),
        httponly=True,
        samesite="lax",
        max_age=_SESSION_MAX_AGE_SECONDS,
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(_SESSION_COOKIE_NAME)


def require_admin_session(request: Request) -> str:
    """Dependency que guarda as rotas novas (auth/endpoints) -- rotas
    existentes (assess/ingest/demo/billing/newsletter) continuam sem auth,
    de propósito, fora de escopo desta etapa.
    """
    cookie_value = request.cookies.get(_SESSION_COOKIE_NAME)
    if not cookie_value:
        raise HTTPException(401, "not authenticated")
    username = verify_session_cookie(cookie_value)
    if username is None:
        raise HTTPException(401, "invalid session")
    return username
