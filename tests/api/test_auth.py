"""Bootstrap de admin único pro modo appliance -- hits a real Postgres
(DATABASE_URL), same pattern as tests/storage/test_postgres.py: skip if
unreachable, clean admin_users before/after so runs don't interfere with
each other.
"""

import psycopg
import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.storage import postgres as db

pytestmark = pytest.mark.integration


@pytest.fixture
def client():
    """A fresh TestClient (and cookie jar) per test -- a module-level
    singleton here would leak the session cookie set by one test's
    /auth/login into every test that runs after it (confirmed: caused
    test_me_without_session_returns_401 to see a still-valid session and
    get 200 instead of 401).
    """
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def clean_admin_users():
    try:
        conn = db.connect()
    except (KeyError, psycopg.OperationalError) as exc:
        pytest.skip(f"no reachable DATABASE_URL configured: {exc}")
    with conn.cursor() as cur:
        cur.execute("DELETE FROM admin_users")
    conn.commit()
    yield
    with conn.cursor() as cur:
        cur.execute("DELETE FROM admin_users")
    conn.commit()
    conn.close()


def test_status_reports_no_admin_before_setup(client):
    response = client.get("/auth/status")

    assert response.status_code == 200
    assert response.json() == {"has_admin": False}


def test_setup_creates_admin_and_sets_session_cookie(client):
    response = client.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})

    assert response.status_code == 200
    assert response.json() == {"username": "admin"}
    assert "invariant_session" in response.cookies


def test_setup_second_time_returns_409(client):
    client.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})

    response = client.post("/auth/setup", json={"username": "someone-else", "password": "x"})

    assert response.status_code == 409


def test_status_reports_admin_after_setup(client):
    client.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})

    response = client.get("/auth/status")

    assert response.json() == {"has_admin": True}


def test_login_wrong_password_returns_401(client):
    client.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})

    response = client.post("/auth/login", json={"username": "admin", "password": "wrong"})

    assert response.status_code == 401


def test_login_unknown_username_returns_401(client):
    response = client.post("/auth/login", json={"username": "nobody", "password": "x"})

    assert response.status_code == 401


def test_login_correct_password_sets_session_cookie(client):
    client.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})

    response = client.post("/auth/login", json={"username": "admin", "password": "trocarSenha123"})

    assert response.status_code == 200
    assert "invariant_session" in response.cookies


def test_me_without_session_returns_401(client):
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_me_with_valid_session_returns_username(client):
    client.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})
    client.post("/auth/login", json={"username": "admin", "password": "trocarSenha123"})

    response = client.get("/auth/me")

    assert response.status_code == 200
    assert response.json() == {"username": "admin"}


def test_me_with_tampered_cookie_returns_401(client):
    client.cookies.set("invariant_session", "bm90YWRtaW4=.deadbeef")

    response = client.get("/auth/me")

    assert response.status_code == 401


def test_logout_clears_session(client):
    client.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})
    client.post("/auth/login", json={"username": "admin", "password": "trocarSenha123"})

    client.post("/auth/logout")
    response = client.get("/auth/me")

    assert response.status_code == 401
