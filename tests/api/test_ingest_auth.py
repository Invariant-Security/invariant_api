"""/ingest/* só com sessão de admin, e /docs, /redoc, /openapi.json fora do ar:
uvicorn de verdade + Postgres real + ingestion real (como test_internal_services)."""

import urllib.error
import urllib.request

import pytest
from live_server import live_server

import ingest_seed
from invariant_api import main
from invariant_api.auth import create_session_cookie
from invariant_api.clients import ingestion_client

ingestion_api = pytest.importorskip("invariant_ingestion.api")

pytestmark = pytest.mark.integration

PATHS = ["/ingest/fetch/x", "/ingest/extract/x", "/ingest/normalize/x"]


@pytest.fixture(scope="module")
def api():
    with live_server(main.app) as url:
        yield url


@pytest.fixture(scope="module")
def ingestion():
    with live_server(ingestion_api.app) as url:
        yield url


@pytest.fixture
def conn():
    conn = ingest_seed.connect_or_skip()
    ingest_seed.clean(conn)
    yield conn
    ingest_seed.clean(conn)
    conn.close()


def _call(url, method="POST", cookie=None):
    req = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
    if cookie:
        req.add_header("Cookie", f"invariant_session={cookie}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


@pytest.mark.parametrize("path", PATHS)
def test_no_cookie_is_401(api, path):
    assert _call(api + path) == 401


@pytest.mark.parametrize("path", PATHS)
def test_forged_cookie_is_401(api, path):
    good = create_session_cookie("admin")
    payload = good.split(".")[0]
    for forged in ("YWRtaW4.deadbeef", f"{payload}.{'0' * 64}", "garbage"):
        assert _call(api + path, cookie=forged) == 401


def test_admin_normalize_unknown_document_reaches_the_db_and_is_422(api, conn):
    assert _call(api + "/ingest/normalize/nao_existe", cookie=create_session_cookie("admin")) == 422


def test_admin_normalize_seeded_document_writes_controls(api, ingestion, conn, monkeypatch):
    monkeypatch.setattr(ingestion_client, "BASE_URL", ingestion)
    ingest_seed.seed(conn)
    assert _call(f"{api}/ingest/normalize/{ingest_seed.SLUG}", cookie=create_session_cookie("admin")) == 200
    assert ingest_seed.control_count(conn) == 1


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_interactive_docs_and_schema_are_gone(api, path):
    assert _call(api + path, method="GET") == 404
