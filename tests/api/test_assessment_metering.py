"""Gate da F1 -- avaliação, consumo, idempotência e atomicidade, com tudo real:
Postgres de teste, invariant_assessment num uvicorn de verdade e o host SSH
de fixture daquele repo (127.0.0.1:22022, `ssh-target` do
tests/fixtures/docker-compose.yml dele).

A credencial do host de fixture é lida do arquivo de testes do assessment
via `ast` (sem executar aquele módulo e sem copiar o valor para este repo).
"""

import ast
import http.server
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from live_server import live_server

from conftest import assert_test_database

_required = os.environ.get("INVARIANT_REQUIRE_INTERNAL_SERVICES") == "1"
try:
    from invariant_assessment.api import app as assessment_app
except ImportError:
    if _required:
        raise
    pytest.skip("serviços internos não instalados nesta venv", allow_module_level=True)

from invariant_contracts import v1
from psycopg.types.json import Jsonb
from invariant_contracts.usage import period_bounds, usage_period

from invariant_api import main
from invariant_api.auth import create_session_cookie
from invariant_api.clients import assessment_client
from invariant_api.storage import postgres as db

pytestmark = pytest.mark.integration

ASSESSMENT_REPO = Path(os.environ.get(
    "INVARIANT_ASSESSMENT_REPO", Path(__file__).resolve().parents[3] / "invariant_assessment"))


def _fixture_credentials() -> dict:
    tree = ast.parse((ASSESSMENT_REPO / "tests" / "test_transport.py").read_text())
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ("_SSH_USER", "_SSH_PASSWORD", "_SSH_PORT"):
                values[node.targets[0].id] = ast.literal_eval(node.value)
    return {"port": values["_SSH_PORT"], "username": values["_SSH_USER"],
            "auth_method": "password", "password": values["_SSH_PASSWORD"]}


SSH = _fixture_credentials()
WRONG_SSH = {**SSH, "password": SSH["password"] + "-errada"}


@pytest.fixture(scope="module")
def services():
    with live_server(assessment_app) as a:
        yield {"assessment": a}


CATALOG_SOURCE = "invariant-f1-teste"


@pytest.fixture(scope="module")
def catalog(services, monkeypatch_module):
    """Catálogo mínimo e próprio: um controle por título que a avaliação real
    do host de fixture devolve, sob uma source só deste teste (apagada no
    fim). Não depende de um catálogo CIS ingerido antes no banco de teste."""
    monkeypatch_module.setattr(assessment_client, "BASE_URL", services["assessment"])
    run = assessment_client.run_assessment_remote(
        host="127.0.0.1", port=SSH["port"], username=SSH["username"], auth_method="password",
        key_material=None, password=SSH["password"])
    conn = db.connect()
    assert_test_database(conn)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM sources WHERE name = %s", (CATALOG_SOURCE,))
        cur.execute("INSERT INTO sources (name, type) VALUES (%s, 'teste') RETURNING id", (CATALOG_SOURCE,))
        source_id = cur.fetchone()[0]
        cur.execute("INSERT INTO documents (source_id, name, document_type) VALUES (%s, %s, 'benchmark') RETURNING id",
                    (source_id, run["document"]))
        cur.execute("INSERT INTO document_versions (document_id, publisher_version, content_hash, retrieved_at, "
                    "raw_artifact_path) VALUES (%s, 'f1-teste', 'f1-teste', now(), '') RETURNING id",
                    (cur.fetchone()[0],))
        version_id = cur.fetchone()[0]
        for i, result in enumerate(run["results"]):
            cur.execute("INSERT INTO controls (document_version_id, external_id, title, normalized_data) "
                        "VALUES (%s, %s, %s, %s)",
                        (version_id, f"F1.{i}", result["titles"][0], Jsonb({"remediation": "", "scored": True})))
    conn.commit()
    yield run["document"]
    with conn.cursor() as cur:
        cur.execute("DELETE FROM controls WHERE document_version_id = %s", (version_id,))
        cur.execute("DELETE FROM document_versions WHERE id = %s", (version_id,))
        cur.execute("DELETE FROM documents WHERE source_id = %s", (source_id,))
        cur.execute("DELETE FROM sources WHERE id = %s", (source_id,))
    conn.commit()
    conn.close()


@pytest.fixture(scope="module")
def monkeypatch_module():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


@pytest.fixture
def api(services, catalog, monkeypatch):
    monkeypatch.setattr(assessment_client, "BASE_URL", services["assessment"])
    client = TestClient(main.app)
    client.cookies.set("invariant_session", create_session_cookie("admin"))
    return client


TABLES = "usage_events, domain_events, idempotency_keys, assessment_summaries, discovery_results, endpoints"


@pytest.fixture(autouse=True)
def clean_db():
    try:
        conn = db.connect()
    except Exception as e:
        pytest.skip(f"Postgres de teste indisponível: {e}")
    assert_test_database(conn)
    with conn.cursor() as cur:
        cur.execute(f"TRUNCATE {TABLES} RESTART IDENTITY CASCADE")
    conn.commit()
    yield conn
    with conn.cursor() as cur:
        cur.execute(f"TRUNCATE {TABLES} RESTART IDENTITY CASCADE")
    conn.commit()
    conn.close()


def _q(conn, sql, *params):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    conn.commit()
    return rows


def _discovered_target(api, address="127.0.0.1", hosts=("127.0.0.1",)) -> int:
    """Alvo criado pela API + resultado de descoberta gravado direto: o que
    está em teste aqui é a medição, não a sonda de portas (coberta em
    test_internal_services) -- e as portas abertas em 127.0.0.1 variam de
    máquina para máquina."""
    created = api.post("/endpoints", json={"address": address})
    assert created.status_code in (200, 201), created.text
    target_id = created.json()["id"]
    with db.connect() as conn:
        for ip in hosts:
            db.insert_discovery_result(conn, endpoint_id=target_id, ip=ip, classification="linux_server",
                                       confidence=0.9, evidence={"open_ports": [22]},
                                       scanned_at=datetime.now(timezone.utc).isoformat())
    return target_id


def _assess(api, target_id, ssh=SSH, key=None, **extra):
    headers = {"Idempotency-Key": key} if key else {}
    return api.post(f"/endpoints/{target_id}/assessments", json={"ssh": ssh, **extra}, headers=headers)


def _billable(conn, moment=None):
    start, end = period_bounds(usage_period(moment or datetime.now(timezone.utc)))
    return db.count_billable_hosts(conn, start=start, end=end)


# --- avaliação real gera resumo + consumo + evento -------------------------

def test_real_ssh_assessment_records_summary_usage_and_event(api, clean_db):
    target = _discovered_target(api)
    resp = _assess(api, target)
    assert resp.status_code == 200, resp.text
    body = v1.AssessmentEnvelope.model_validate(resp.json())
    assert body.findings and body.findings_omitted_reason is None
    assert body.assessed_ip == "127.0.0.1" and body.source == "console"
    summaries = _q(clean_db, "SELECT public_id, assessed_ip, source FROM assessment_summaries")
    usage = _q(clean_db, "SELECT host_kind, host_key, assessment_public_id FROM usage_events")
    events = _q(clean_db, "SELECT event_type, payload->>'assessment_id' FROM domain_events")
    assert [(str(s[0]), s[1], s[2]) for s in summaries] == [(str(body.assessment_id), "127.0.0.1", "console")]
    assert [(u[0], u[1], str(u[2])) for u in usage] == [("linux_host", "127.0.0.1", str(body.assessment_id))]
    assert events == [("assessment.completed", str(body.assessment_id))]


def test_same_host_three_times_in_the_month_is_one_unit(api, clean_db):
    target = _discovered_target(api)
    for _ in range(3):
        assert _assess(api, target).status_code == 200
    assert _q(clean_db, "SELECT count(*) FROM usage_events") == [(3,)]
    assert _billable(clean_db) == {"linux_host": 1, "docker_container": 0}


def test_next_month_is_a_new_unit_regardless_of_session_timezone(clean_db):
    with clean_db.cursor() as cur:
        cur.execute("SET TIME ZONE 'America/Sao_Paulo'")
    for moment in ("2026-09-15T10:00:00Z", "2026-09-30T23:59:59.999999Z", "2026-10-01T00:00:00Z"):
        db.insert_usage_event(clean_db, occurred_at=moment, host_kind="linux_host", host_key="10.0.0.5",
                              source="console", endpoint_id=None, assessment_public_id=None)
    clean_db.commit()
    september = datetime(2026, 9, 10, tzinfo=timezone.utc)
    october = datetime(2026, 10, 10, tzinfo=timezone.utc)
    assert _billable(clean_db, september)["linux_host"] == 1
    assert _billable(clean_db, october)["linux_host"] == 1


def test_ssh_failure_records_nothing(api, clean_db):
    target = _discovered_target(api)
    resp = _assess(api, target, ssh=WRONG_SSH)
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "ssh_auth_failed"
    for table in ("assessment_summaries", "usage_events", "domain_events", "idempotency_keys"):
        assert _q(clean_db, f"SELECT count(*) FROM {table}") == [(0,)], table


def test_deleting_the_target_keeps_consumption(api, clean_db):
    target = _discovered_target(api)
    assert _assess(api, target).status_code == 200
    assert api.delete(f"/endpoints/{target}").status_code in (200, 204)
    assert _q(clean_db, "SELECT count(*) FROM assessment_summaries") == [(0,)]
    assert _q(clean_db, "SELECT count(*) FROM usage_events") == [(1,)]
    assert _billable(clean_db)["linux_host"] == 1


# --- IP validado antes de qualquer conexão -----------------------------------

class _Recorder(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_POST(self):
        type(self).hits += 1
        self.send_response(500)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def recording_assessment(api, monkeypatch):
    """Um servidor HTTP real no lugar do assessment, que só conta acessos --
    prova que a recusa acontece antes de qualquer conexão sair do api."""
    _Recorder.hits = 0
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(assessment_client, "BASE_URL", f"http://127.0.0.1:{server.server_address[1]}")
    yield _Recorder
    server.shutdown()


def test_ip_outside_the_target_is_refused_before_connecting(api, clean_db, recording_assessment):
    target = _discovered_target(api)
    resp = _assess(api, target, ip="10.0.0.5")
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "ip_not_in_target"
    assert recording_assessment.hits == 0


def test_ip_in_the_cidr_but_not_discovered_is_refused_before_connecting(api, clean_db, recording_assessment):
    target = _discovered_target(api, address="10.9.0.0/24", hosts=("10.9.0.5",))
    resp = _assess(api, target, ip="10.9.0.6")
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "target_not_discovered"
    assert recording_assessment.hits == 0


def test_target_never_discovered_is_refused_before_connecting(api, clean_db, recording_assessment):
    target = api.post("/endpoints", json={"address": "10.8.0.1"}).json()["id"]
    resp = _assess(api, target)
    assert resp.status_code == 422 and resp.json()["detail"]["code"] == "target_not_discovered"
    assert recording_assessment.hits == 0


# --- Idempotency-Key ----------------------------------------------------------

def test_same_key_returns_the_same_operation_without_running_again(api, clean_db):
    target = _discovered_target(api)
    first = _assess(api, target, key="chave-1")
    second = _assess(api, target, key="chave-1")
    assert first.status_code == second.status_code == 200
    a, b = first.json(), second.json()
    assert a["assessment_id"] == b["assessment_id"] and a["summary"] == b["summary"]
    assert a["findings"] and b["findings"] is None and b["findings_omitted_reason"] == "not_stored"
    assert _q(clean_db, "SELECT count(*) FROM usage_events") == [(1,)]
    assert _q(clean_db, "SELECT count(*) FROM assessment_summaries") == [(1,)]


def test_same_key_with_a_different_request_is_a_mismatch(api, clean_db, recording_assessment):
    target = _discovered_target(api)
    # chave registrada como concluída para um pedido...
    with clean_db.cursor() as cur:
        cur.execute("INSERT INTO idempotency_keys (principal, idem_key, route, fingerprint, state, response_status, "
                    "response_body) VALUES ('admin:admin', 'chave-2', 'POST /endpoints/{id}/assessments', 'outro', "
                    "'completed', 200, '{}')")
    clean_db.commit()
    resp = _assess(api, target, key="chave-2")
    assert resp.status_code == 422 and resp.json()["detail"]["code"] == "idempotency_mismatch"
    assert recording_assessment.hits == 0


def test_mismatch_after_a_real_completed_run(api, clean_db):
    target = _discovered_target(api)
    assert _assess(api, target, key="chave-3").status_code == 200
    changed = _assess(api, target, ssh={**SSH, "port": 2222}, key="chave-3")
    assert changed.status_code == 422 and changed.json()["detail"]["code"] == "idempotency_mismatch"
    assert _q(clean_db, "SELECT count(*) FROM usage_events") == [(1,)]


def test_password_is_not_part_of_the_request_identity(api, clean_db):
    target = _discovered_target(api)
    assert _assess(api, target, key="chave-4").status_code == 200
    replay = _assess(api, target, ssh={**SSH, "password": "qualquer-outra"}, key="chave-4")
    assert replay.status_code == 200 and replay.json()["findings_omitted_reason"] == "not_stored"
    stored = _q(clean_db, "SELECT fingerprint, response_body::text FROM idempotency_keys")
    assert SSH["password"] not in "".join(stored[0])


def test_key_in_progress_is_refused_and_a_stale_one_is_taken_over(api, clean_db):
    target = _discovered_target(api)
    fp = __import__("invariant_api.assessment_runs", fromlist=["x"]).fingerprint(
        "POST /endpoints/{id}/assessments", target, v1.AssessmentRequest(ssh=SSH))
    with clean_db.cursor() as cur:
        cur.execute("INSERT INTO idempotency_keys (principal, idem_key, route, fingerprint, state) "
                    "VALUES ('admin:admin', 'chave-5', 'POST /endpoints/{id}/assessments', %s, 'in_progress')", (fp,))
    clean_db.commit()
    busy = _assess(api, target, key="chave-5")
    assert busy.status_code == 409 and busy.json()["detail"]["code"] == "idempotency_in_progress"
    _exec(clean_db, "UPDATE idempotency_keys SET updated_at = now() - interval '11 minutes'")
    taken = _assess(api, target, key="chave-5")
    assert taken.status_code == 200, taken.text
    assert _q(clean_db, "SELECT state FROM idempotency_keys") == [("completed",)]


def test_failed_execution_releases_the_key(api, clean_db):
    target = _discovered_target(api)
    failed = _assess(api, target, ssh=WRONG_SSH, key="chave-6")
    assert failed.status_code == 401
    assert _q(clean_db, "SELECT count(*) FROM idempotency_keys") == [(0,)]
    retried = _assess(api, target, key="chave-6")
    assert retried.status_code == 200 and retried.json()["findings"]


# --- atomicidade ----------------------------------------------------------------

_DROP_TRIGGER = "DROP TRIGGER IF EXISTS f1_falha ON domain_events; DROP FUNCTION IF EXISTS f1_falha()"


def _exec(conn, sql):
    with conn.cursor() as cur:
        cur.execute(sql)
    conn.commit()


@pytest.fixture
def failing_domain_events(clean_db):
    """Falha real dentro da transação: um trigger que recusa o ÚLTIMO insert
    antes do commit (o evento de domínio), depois de resumo e consumo já
    terem sido inseridos na mesma transação."""
    _exec(clean_db, _DROP_TRIGGER)
    try:
        _exec(clean_db, "CREATE FUNCTION f1_falha() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'falha forçada'; "
                        "END $$ LANGUAGE plpgsql")
        _exec(clean_db, "CREATE TRIGGER f1_falha BEFORE INSERT ON domain_events FOR EACH ROW "
                        "EXECUTE FUNCTION f1_falha()")
        yield
    finally:
        clean_db.rollback()
        _exec(clean_db, _DROP_TRIGGER)


def test_forced_failure_inside_the_transaction_persists_nothing(api, clean_db, failing_domain_events):
    target = _discovered_target(api)
    resp = _assess(api, target, key="chave-7")
    assert resp.status_code == 500 and resp.json()["detail"]["code"] == "internal_error"
    for table in ("assessment_summaries", "usage_events", "domain_events", "idempotency_keys"):
        assert _q(clean_db, f"SELECT count(*) FROM {table}") == [(0,)], table
    old = api.post(f"/endpoints/{target}/assess", json=SSH)
    assert old.status_code == 500
    assert _q(clean_db, "SELECT count(*) FROM usage_events") == [(0,)]


# --- rota antiga ------------------------------------------------------------------

def test_old_route_keeps_its_format_and_now_records_consumption(api, clean_db):
    target = _discovered_target(api)
    resp = api.post(f"/endpoints/{target}/assess", json=SSH)
    assert resp.status_code == 200
    findings = resp.json()
    assert isinstance(findings, list) and findings
    assert {"external_id", "status", "control_title", "evidence_output"} <= set(findings[0])
    assert _q(clean_db, "SELECT source, assessed_ip FROM assessment_summaries") == [("console", "127.0.0.1")]
    assert _billable(clean_db)["linux_host"] == 1


def test_reading_back_an_assessment_has_no_findings(api, clean_db):
    target = _discovered_target(api)
    created = _assess(api, target).json()
    listed = api.get(f"/endpoints/{target}/assessments").json()
    assert [i["assessment_id"] for i in listed] == [created["assessment_id"]]
    assert listed[0]["findings_stored"] is False
    one = api.get(f"/endpoints/{target}/assessments/{created['assessment_id']}").json()
    assert one["findings"] is None and one["findings_omitted_reason"] == "not_stored"
    assert one["summary"] == created["summary"]
