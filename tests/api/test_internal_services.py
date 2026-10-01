"""Teste arquitetural da autenticação interna, com os 3 serviços REAIS.

Cada serviço (invariant_assessment, invariant_discovery, invariant_ingestion)
sobe num uvicorn de verdade, numa porta local, com o próprio token. Prova:
- chamada direta sem passar pelo api é recusada (rede não é autenticação);
- o token de um serviço não abre outro (nada de token compartilhado);
- pelos clientes do api, com o token certo de cada um, o fluxo funciona;
- a rota HTTP do console (POST /endpoints/{id}/discover) chega ao discovery real.

Requer os 3 pacotes instalados na venv de testes (o CI instala a partir dos
checkouts irmãos). INVARIANT_REQUIRE_INTERNAL_SERVICES=1 transforma a
ausência deles em falha em vez de skip.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest
import uvicorn
from fastapi.testclient import TestClient

from conftest import assert_test_database

_required = os.environ.get("INVARIANT_REQUIRE_INTERNAL_SERVICES") == "1"
try:
    from invariant_assessment.api import app as assessment_app
    from invariant_discovery.api import app as discovery_app
    from invariant_ingestion.api import app as ingestion_app
except ImportError:
    if _required:
        raise
    pytest.skip("serviços internos não instalados nesta venv", allow_module_level=True)

from invariant_api import main
from invariant_api.auth import create_session_cookie
from invariant_api.clients import assessment_client, discovery_client, ingestion_client
from invariant_api.clients.internal_auth import (
    ASSESSMENT_TOKEN_ENV,
    DISCOVERY_TOKEN_ENV,
    INGESTION_TOKEN_ENV,
)
from invariant_api.storage import postgres as db

pytestmark = pytest.mark.integration

TOKENS = {
    ASSESSMENT_TOKEN_ENV: "arch-assessment-" + "1" * 40,
    DISCOVERY_TOKEN_ENV: "arch-discovery-" + "2" * 40,
    INGESTION_TOKEN_ENV: "arch-ingestion-" + "3" * 40,
}


def _start(app):
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started:
        assert time.time() < deadline, "serviço não subiu"
        time.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    return server, thread, f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def services():
    previous = {name: os.environ.get(name) for name in TOKENS}
    os.environ.update(TOKENS)
    started = {name: _start(app) for name, app in (
        ("assessment", assessment_app), ("discovery", discovery_app), ("ingestion", ingestion_app))}
    urls = {name: s[2] for name, s in started.items()}
    yield urls
    for server, thread, _ in started.values():
        server.should_exit = True
        thread.join(timeout=10)
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


@pytest.fixture
def api_points_to_services(services, monkeypatch):
    monkeypatch.setattr(assessment_client, "BASE_URL", services["assessment"])
    monkeypatch.setattr(discovery_client, "BASE_URL", services["discovery"])
    monkeypatch.setattr(ingestion_client, "BASE_URL", services["ingestion"])
    return services


def _call(url, method, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


OPERATIONS = {
    "assessment": ("/assessment/containers", "GET", None, ASSESSMENT_TOKEN_ENV),
    "discovery": ("/discover", "POST", {"addresses": ["127.0.0.1"]}, DISCOVERY_TOKEN_ENV),
    "ingestion": ("/ingestion/normalize", "POST", [], INGESTION_TOKEN_ENV),
}


@pytest.mark.parametrize("service", OPERATIONS)
def test_direct_call_without_token_is_refused(services, service):
    path, method, body, _ = OPERATIONS[service]
    assert _call(services[service] + path, method, body) == 401


@pytest.mark.parametrize("service", OPERATIONS)
def test_another_services_token_does_not_open_this_one(services, service):
    path, method, body, own = OPERATIONS[service]
    for other in (name for name in TOKENS if name != own):
        assert _call(services[service] + path, method, body, token=TOKENS[other]) == 401


@pytest.mark.parametrize("service", OPERATIONS)
def test_direct_call_with_own_token_works(services, service):
    path, method, body, own = OPERATIONS[service]
    assert _call(services[service] + path, method, body, token=TOKENS[own]) == 200


def test_api_clients_reach_all_three_services(api_points_to_services):
    results = discovery_client.discover(["127.0.0.1"])
    assert [r["ip"] for r in results] == ["127.0.0.1"]
    assert ingestion_client.normalize([]) == []
    assert isinstance(assessment_client.list_containers(), list)


def test_api_client_without_its_token_fails_closed(api_points_to_services, monkeypatch):
    monkeypatch.delenv(DISCOVERY_TOKEN_ENV)
    with pytest.raises(RuntimeError, match=DISCOVERY_TOKEN_ENV):
        discovery_client.discover(["127.0.0.1"])


@pytest.fixture
def clean_endpoints():
    try:
        conn = db.connect()
    except Exception as e:  # sem banco de teste disponível
        pytest.skip(f"Postgres de teste indisponível: {e}")
    assert_test_database(conn)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM discovery_results; DELETE FROM endpoints;")
    conn.commit()
    yield
    with conn.cursor() as cur:
        cur.execute("DELETE FROM discovery_results; DELETE FROM endpoints;")
    conn.commit()
    conn.close()


def test_console_route_reaches_real_discovery(api_points_to_services, clean_endpoints):
    client = TestClient(main.app)
    client.cookies.set("invariant_session", create_session_cookie("admin"))
    created = client.post("/endpoints", json={"address": "127.0.0.1"})
    assert created.status_code in (200, 201), created.text
    endpoint_id = created.json()["id"]
    discovered = client.post(f"/endpoints/{endpoint_id}/discover")
    assert discovered.status_code == 200, discovered.text
    assert [r["ip"] for r in discovered.json()] == ["127.0.0.1"]
