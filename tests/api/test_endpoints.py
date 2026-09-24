"""CRUD de /endpoints + gatilho de discovery -- hits a real Postgres
(DATABASE_URL) same as tests/storage/test_postgres.py. discovery_client is
monkeypatched (invariant_discovery is a separate service/repo, not
exercised here -- see invariant_discovery's own tests for the scanning
logic itself).
"""

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.clients import assessment_client, discovery_client
from invariant_api.storage import postgres as db

from conftest import assert_test_database

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def clean_tables():
    try:
        conn = db.connect()
    except (KeyError, psycopg.OperationalError) as exc:
        pytest.skip(f"no reachable DATABASE_URL configured: {exc}")
    assert_test_database(conn)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM assessment_summaries")
        cur.execute("DELETE FROM discovery_results")
        cur.execute("DELETE FROM endpoints")
        cur.execute("DELETE FROM admin_users")
    conn.commit()
    yield
    with conn.cursor() as cur:
        cur.execute("DELETE FROM assessment_summaries")
        cur.execute("DELETE FROM discovery_results")
        cur.execute("DELETE FROM endpoints")
        cur.execute("DELETE FROM admin_users")
    conn.commit()
    conn.close()


@pytest.fixture
def session_client():
    """A logged-in TestClient -- every /endpoints route requires an admin
    session (routes/endpoints.py's `dependencies=[Depends(require_admin_session)]`).
    """
    c = TestClient(main.app)
    c.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})
    return c


def test_endpoints_require_auth():
    anonymous = TestClient(main.app)

    response = anonymous.get("/endpoints")

    assert response.status_code == 401


def test_create_endpoint_rejects_invalid_address(session_client):
    response = session_client.post("/endpoints", json={"address": "not-an-ip"})

    assert response.status_code == 422


def test_create_and_list_single_ip_endpoint(session_client):
    create = session_client.post("/endpoints", json={"address": "10.0.0.5", "label": "gateway"})
    assert create.status_code == 200

    listed = session_client.get("/endpoints").json()

    assert len(listed) == 1
    assert listed[0]["address"] == "10.0.0.5"
    assert listed[0]["label"] == "gateway"
    assert listed[0]["classification"] is None  # nenhuma discovery rodou ainda


def test_create_cidr_range_endpoint(session_client):
    response = session_client.post("/endpoints", json={"address": "10.0.0.0/24", "tags": ["filial-sp"]})

    assert response.status_code == 200
    assert response.json()["address"] == "10.0.0.0/24"


def test_list_annotates_is_demo_for_addresses_inside_the_reserved_range(session_client):
    session_client.post("/endpoints", json={"address": "10.89.77.11", "label": "demo-host-web-01"})

    listed = session_client.get("/endpoints").json()

    assert len(listed) == 1
    assert listed[0]["is_demo"] is True


def test_list_annotates_is_demo_false_for_real_addresses(session_client):
    session_client.post("/endpoints", json={"address": "10.0.0.5", "label": "gateway"})

    listed = session_client.get("/endpoints").json()

    assert listed[0]["is_demo"] is False


def test_list_annotates_is_demo_false_for_cidr_ranges_even_inside_the_reserved_network(session_client):
    # is_demo_endpoint só é True pra um IP único -- uma faixa CIDR
    # nunca é elegível, mesmo se estiver dentro de 10.89.77.0/24.
    session_client.post("/endpoints", json={"address": "10.89.77.0/28", "tags": []})

    listed = session_client.get("/endpoints").json()

    assert listed[0]["is_demo"] is False


# --- POST /endpoints/bulk (CSV import) ---


def test_bulk_endpoint_registered_before_dynamic_routes(session_client):
    """A rota estática /bulk precisa ganhar de qualquer /{endpoint_id}/...
    dinâmica -- confirma que bate no handler de bulk (aceita uma lista),
    não em alguma rota dinâmica tentando interpretar "bulk" como id.
    """
    response = session_client.post("/endpoints/bulk", json=[])

    assert response.status_code == 200
    assert response.json() == []


def test_bulk_create_endpoints_mixed_valid_and_invalid(session_client):
    response = session_client.post(
        "/endpoints/bulk",
        json=[
            {"row": 2, "address": "10.0.0.10", "label": "API"},
            {"row": 3, "address": "not-an-ip", "label": "Ruim"},
            {"row": 5, "address": "10.0.0.11", "label": "Banco"},
        ],
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 3

    created = {r["row"]: r for r in body if r["status"] == "created"}
    errors = {r["row"]: r for r in body if r["status"] == "error"}

    assert set(created) == {2, 5}
    assert created[2]["id"] is not None
    assert created[5]["id"] is not None

    assert set(errors) == {3}
    assert errors[3]["detail"] == "Endereço IP ou CIDR inválido."
    assert errors[3]["id"] is None

    # As válidas realmente foram persistidas -- uma linha inválida no meio
    # não impediu as seguintes.
    listed = {e["address"] for e in session_client.get("/endpoints").json()}
    assert listed == {"10.0.0.10", "10.0.0.11"}


def test_bulk_create_endpoints_duplicate_already_in_db(session_client):
    session_client.post("/endpoints", json={"address": "10.0.0.20"})

    response = session_client.post(
        "/endpoints/bulk",
        json=[{"row": 2, "address": "10.0.0.20", "label": "Já existe"}],
    )

    assert response.status_code == 200
    result = response.json()[0]
    assert result["status"] == "error"
    assert result["detail"] == "Este endereço já está cadastrado."


def test_bulk_create_endpoints_duplicate_within_same_payload(session_client):
    response = session_client.post(
        "/endpoints/bulk",
        json=[
            {"row": 2, "address": "10.0.0.30"},
            {"row": 3, "address": "10.0.0.30"},
        ],
    )

    assert response.status_code == 200
    body = response.json()
    assert body[0]["row"] == 2 and body[0]["status"] == "created"
    assert body[1]["row"] == 3 and body[1]["status"] == "error"
    assert body[1]["detail"] == "Este endereço já está cadastrado."


def test_bulk_row_number_reflects_original_file_line_not_array_position():
    """Simula exatamente o caso levantado na revisão: cabeçalho na linha 1,
    dado na linha 2, linha 3 vazia (nunca chega no backend -- o frontend
    filtra antes), erro na linha 4. O payload que chega aqui já teria
    row=2 e row=4 -- o backend só precisa preservar isso, não deduzir.
    """
    client = TestClient(main.app)
    client.post("/auth/setup", json={"username": "admin", "password": "trocarSenha123"})

    response = client.post(
        "/endpoints/bulk",
        json=[
            {"row": 2, "address": "10.0.0.40", "label": "OK"},
            {"row": 4, "address": "999.1.1.1", "label": "Ruim"},
        ],
    )

    assert response.status_code == 200
    body = response.json()
    assert body[0]["row"] == 2
    assert body[1]["row"] == 4  # nunca 3, que seria a posição no array
    assert body[1]["status"] == "error"


def test_bulk_rejects_more_than_max_endpoints(session_client):
    payload = [{"row": i, "address": f"10.0.{i // 256}.{i % 256}"} for i in range(501)]

    response = session_client.post("/endpoints/bulk", json=payload)

    assert response.status_code == 422
    assert session_client.get("/endpoints").json() == []  # nada foi inserido


def test_bulk_endpoints_requires_auth():
    anonymous = TestClient(main.app)

    response = anonymous.post("/endpoints/bulk", json=[{"row": 1, "address": "10.0.0.5"}])

    assert response.status_code == 401


def test_delete_endpoint(session_client):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]

    delete = session_client.delete(f"/endpoints/{endpoint_id}")
    assert delete.status_code == 200

    assert session_client.get("/endpoints").json() == []


def test_delete_missing_endpoint_returns_404(session_client):
    response = session_client.delete("/endpoints/999999")

    assert response.status_code == 404


def test_discover_persists_results_and_they_show_in_list(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5", "label": "gateway"}).json()["id"]

    fake_result = {
        "ip": "10.0.0.5",
        "classification": "linux",
        "confidence": 0.82,
        "evidence": {"open_ports": [22], "banners": {"22": "SSH-2.0-OpenSSH_9.2 Debian"}},
        "scanned_at": "2026-09-02T00:00:00+00:00",
    }
    monkeypatch.setattr(discovery_client, "discover", lambda addresses: [fake_result])

    response = session_client.post(f"/endpoints/{endpoint_id}/discover")

    assert response.status_code == 200
    assert response.json() == [fake_result]

    listed = session_client.get("/endpoints").json()
    assert listed[0]["classification"] == "linux"
    assert listed[0]["confidence"] == pytest.approx(0.82)

    # scanned_at round-trips through a TIMESTAMPTZ column -- Postgres/psycopg
    # preserve the instant, not the exact "+00:00" vs "Z" spelling (confirmed:
    # comes back "...00:00:00Z" here even though "+00:00" was sent in), so
    # compare everything except that field exactly and parse scanned_at.
    results = session_client.get(f"/endpoints/{endpoint_id}/results").json()
    assert len(results) == 1
    result = results[0]
    assert {k: v for k, v in result.items() if k != "scanned_at"} == {
        k: v for k, v in fake_result.items() if k != "scanned_at"
    }
    assert result["scanned_at"].replace("Z", "+00:00") == fake_result["scanned_at"]


def test_discover_missing_endpoint_returns_404(session_client):
    response = session_client.post("/endpoints/999999/discover")

    assert response.status_code == 404


def test_discover_propagates_discovery_service_failure_as_502(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]

    def boom(addresses):
        raise ConnectionError("invariant_discovery unreachable")

    monkeypatch.setattr(discovery_client, "discover", boom)

    response = session_client.post(f"/endpoints/{endpoint_id}/discover")

    assert response.status_code == 502


# --- POST /endpoints/{id}/assess (SSH-based remote assessment) ---
#
# _findings_from_run() joins each invariant_assessment result against
# Postgres control metadata (db.select_control_by_title, called from
# invariant_api.routes.assess) -- monkeypatched here the same way
# discovery_client is monkeypatched above, since invariant_assessment
# itself is a separate service/repo not exercised by this suite.

_FAKE_DISCOVERY_RESULT = {
    "ip": "10.0.0.5",
    "classification": "linux",
    "confidence": 0.91,
    "evidence": {"open_ports": [22], "banners": {"22": "SSH-2.0-OpenSSH_9.2 Debian"}},
    "scanned_at": "2026-09-02T00:00:00+00:00",
}

_FAKE_CONTROL = {
    "external_id": "1.1.1",
    "title": "Ensure SSH PermitRootLogin is disabled",
    "source_name": "CIS",
    "document_name": "CIS Debian Linux 12 Benchmark",
    "publisher_version": "1.0.0",
    "normalized_data": {"remediation": "Set PermitRootLogin to no.", "applicability": [{"level": 1}], "scored": True},
    "raw_artifact_path": "raw/debian12.json",
    "content_hash": "deadbeef",
    "retrieved_at": None,
}

_FAKE_RUN = {
    "document": "debian_linux_12",
    "results": [
        {
            "titles": ["Ensure SSH PermitRootLogin is disabled"],
            "status": "FAIL",
            "evidence": "PermitRootLogin yes",
        }
    ],
}


def _discover_endpoint(session_client, monkeypatch, endpoint_id):
    monkeypatch.setattr(discovery_client, "discover", lambda addresses: [_FAKE_DISCOVERY_RESULT])
    response = session_client.post(f"/endpoints/{endpoint_id}/discover")
    assert response.status_code == 200


def test_assess_discovered_endpoint_requires_discovery_first(session_client):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]

    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 422


def test_assess_discovered_endpoint_calls_assessment_client_with_ip_and_credentials(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    captured = {}

    def fake_run_assessment_remote(**kwargs):
        captured.update(kwargs)
        return _FAKE_RUN

    monkeypatch.setattr(assessment_client, "run_assessment_remote", fake_run_assessment_remote)
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: _FAKE_CONTROL)

    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["control_title"] == "Ensure SSH PermitRootLogin is disabled"
    assert body[0]["status"] == "FAIL"

    assert captured["host"] == "10.0.0.5"
    assert captured["username"] == "root"
    assert captured["auth_method"] == "password"
    assert captured["password"] == "hunter2"
    assert body[0]["target_type"] == "linux_host"


def test_assess_discovered_endpoint_propagates_assessment_service_error(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    def boom(**kwargs):
        request = httpx.Request("POST", "http://assessment:8000/assessment/run-remote")
        response = httpx.Response(401, request=request, text="bad SSH credentials")
        raise httpx.HTTPStatusError("401", request=request, response=response)

    monkeypatch.setattr(assessment_client, "run_assessment_remote", boom)

    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "wrong"},
    )

    assert response.status_code == 401


def test_assess_discovered_endpoint_requires_auth():
    anonymous = TestClient(main.app)

    response = anonymous.post(
        "/endpoints/1/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 401


# --- assessment_summaries: lightweight persisted resumo, GET /endpoints
# reflecting it -- ver invariant_api.reports.split_findings()/
# compliance_pct(), reaproveitadas aqui, não reimplementadas. Um run com
# 5 controles distintos, cada um provocando um bucket diferente:
# Control A (PASS) -> applicable_pass; Control B (FAIL) -> applicable_fail;
# Control C (FAIL, evidence carrega o sentinel "sshd ausente") -> também
# applicable_fail (seu próprio (doc,id) não está em SSHD_DEPENDENT_CONTROLS),
# mas faz ssh_state() virar "absent" pro restante do batch; Control D
# ((debian_linux_12, 5.1.1), um dos pares reais em SSHD_DEPENDENT_CONTROLS)
# -> not_applicable, já que sshd está "absent"; Control E (status "MANUAL",
# fora do domínio PASS/FAIL -- Finding.status é str livre, sem Literal, então
# isso nem precisa de bypass de validação) -> not_assessed.

_SSH_ABSENT_SENTINEL = "<sshd-not-installed>"

_MULTI_FAKE_RUN = {
    "document": "debian_linux_12",
    "results": [
        {"titles": ["Control A - Pass"], "status": "PASS", "evidence": "ok"},
        {"titles": ["Control B - Fail"], "status": "FAIL", "evidence": "bad"},
        {"titles": ["Control C - SSH probe"], "status": "FAIL", "evidence": _SSH_ABSENT_SENTINEL},
        {"titles": ["Control D - SSH dependent"], "status": "FAIL", "evidence": "sshd_config: PermitRootLogin yes"},
        {"titles": ["Control E - Manual"], "status": "MANUAL", "evidence": "n/a"},
    ],
}

_MULTI_FAKE_CONTROLS_BY_TITLE = {
    "Control A - Pass": {**_FAKE_CONTROL, "external_id": "9.9.1", "title": "Control A - Pass", "document_name": "debian_linux_12"},
    "Control B - Fail": {**_FAKE_CONTROL, "external_id": "9.9.2", "title": "Control B - Fail", "document_name": "debian_linux_12"},
    "Control C - SSH probe": {**_FAKE_CONTROL, "external_id": "9.9.3", "title": "Control C - SSH probe", "document_name": "debian_linux_12"},
    # (debian_linux_12, 5.1.1) is a real entry in finding_taxonomy.SSHD_DEPENDENT_CONTROLS.
    "Control D - SSH dependent": {**_FAKE_CONTROL, "external_id": "5.1.1", "title": "Control D - SSH dependent", "document_name": "debian_linux_12"},
    "Control E - Manual": {**_FAKE_CONTROL, "external_id": "9.9.5", "title": "Control E - Manual", "document_name": "debian_linux_12"},
}


def _fake_select_control_by_title(conn, *, document, titles):
    return _MULTI_FAKE_CONTROLS_BY_TITLE[titles[0]]


def _run_multi_assess(session_client, monkeypatch, endpoint_id):
    monkeypatch.setattr(assessment_client, "run_assessment_remote", lambda **kwargs: _MULTI_FAKE_RUN)
    monkeypatch.setattr(db, "select_control_by_title", _fake_select_control_by_title)
    return session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )


def test_assess_persists_summary_and_it_shows_in_list(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    response = _run_multi_assess(session_client, monkeypatch, endpoint_id)
    assert response.status_code == 200
    # response contract unchanged -- still exactly list[Finding], no new field.
    assert len(response.json()) == 5

    listed = session_client.get("/endpoints").json()
    endpoint = next(e for e in listed if e["id"] == endpoint_id)
    assert endpoint["last_assessment_target_type"] == "linux_host"
    assert endpoint["last_assessment_pass_count"] == 1
    assert endpoint["last_assessment_fail_count"] == 2
    assert endpoint["last_assessment_not_assessed_count"] == 1
    assert endpoint["last_assessment_not_applicable_count"] == 1
    assert endpoint["last_assessment_compliance_pct"] == 33  # round(100 * 1/3)
    assert endpoint["last_assessed_at"] is not None


def test_assess_never_run_returns_null_summary_fields(session_client):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]

    listed = session_client.get("/endpoints").json()
    endpoint = next(e for e in listed if e["id"] == endpoint_id)
    for field in (
        "last_assessment_target_type",
        "last_assessment_pass_count",
        "last_assessment_fail_count",
        "last_assessment_not_assessed_count",
        "last_assessment_not_applicable_count",
        "last_assessment_compliance_pct",
        "last_assessed_at",
    ):
        assert endpoint[field] is None


def test_assess_twice_keeps_history_and_list_surfaces_latest(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    # First run: single-control fake (_FAKE_RUN), 1 FAIL, 0 PASS.
    monkeypatch.setattr(assessment_client, "run_assessment_remote", lambda **kwargs: _FAKE_RUN)
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: _FAKE_CONTROL)
    first = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )
    assert first.status_code == 200

    # Second run: the 5-control multi-fake -- different composition entirely.
    second = _run_multi_assess(session_client, monkeypatch, endpoint_id)
    assert second.status_code == 200

    listed = session_client.get("/endpoints").json()
    endpoint = next(e for e in listed if e["id"] == endpoint_id)
    # Only the second (latest) run's counts are surfaced.
    assert endpoint["last_assessment_pass_count"] == 1
    assert endpoint["last_assessment_fail_count"] == 2

    conn = db.connect()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM assessment_summaries WHERE endpoint_id = %(id)s", {"id": endpoint_id})
        count = cur.fetchone()[0]
    conn.close()
    assert count == 2  # append-only history, never an upsert


def test_assess_failure_does_not_erase_last_valid_summary(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    ok = _run_multi_assess(session_client, monkeypatch, endpoint_id)
    assert ok.status_code == 200

    def boom(**kwargs):
        request = httpx.Request("POST", "http://assessment:8000/assessment/run-remote")
        response = httpx.Response(401, request=request, text="bad SSH credentials")
        raise httpx.HTTPStatusError("401", request=request, response=response)

    monkeypatch.setattr(assessment_client, "run_assessment_remote", boom)
    failed = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "wrong"},
    )
    assert failed.status_code == 401

    listed = session_client.get("/endpoints").json()
    endpoint = next(e for e in listed if e["id"] == endpoint_id)
    assert endpoint["last_assessment_pass_count"] == 1
    assert endpoint["last_assessment_fail_count"] == 2

    conn = db.connect()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM assessment_summaries WHERE endpoint_id = %(id)s", {"id": endpoint_id})
        count = cur.fetchone()[0]
    conn.close()
    assert count == 1  # the failed attempt never inserted a row


def test_assessment_summary_never_stores_finding_evidence_or_titles(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    marker = "SUPER-SECRET-EVIDENCE-MARKER-XYZ"
    marked_run = {
        "document": "debian_linux_12",
        "results": [{"titles": [marker], "status": "FAIL", "evidence": marker}],
    }
    marked_control = {**_FAKE_CONTROL, "title": marker, "normalized_data": {**_FAKE_CONTROL["normalized_data"], "remediation": marker}}
    monkeypatch.setattr(assessment_client, "run_assessment_remote", lambda **kwargs: marked_run)
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: marked_control)

    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )
    assert response.status_code == 200

    conn = db.connect()
    _assert_marker_absent_from_table(conn, "assessment_summaries", marker)
    conn.close()


# --- POST /endpoints/{id}/check (SSH pre-flight, mirrors GET /containers/{name}/check) ---


def test_check_endpoint_requires_discovery_first(session_client):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]

    response = session_client.post(
        f"/endpoints/{endpoint_id}/check",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 422


def test_check_endpoint_returns_target_type_and_primary_ip(session_client, monkeypatch):
    endpoint_id = session_client.post(
        "/endpoints", json={"address": "10.0.0.5", "label": "invariant-demo-linux"}
    ).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    monkeypatch.setattr(
        assessment_client,
        "check_remote",
        lambda **kwargs: {
            "testable": True,
            "os_id": "debian",
            "os_version_id": "13",
            "family": "debian_ubuntu",
            "reason_code": None,
            "reason": None,
            "hostname": "invariant-demo-linux",
        },
    )

    response = session_client.post(
        f"/endpoints/{endpoint_id}/check",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["testable"] is True
    assert body["target_type"] == "linux_host"
    assert body["primary_ip"] == "10.0.0.5"  # the endpoint's own stored address, not the discovery ip
    assert body["hostname"] == "invariant-demo-linux"


def test_check_endpoint_propagates_assessment_service_error(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    def boom(**kwargs):
        request = httpx.Request("POST", "http://assessment:8000/assessment/check-remote")
        response = httpx.Response(401, request=request, text="bad SSH credentials")
        raise httpx.HTTPStatusError("401", request=request, response=response)

    monkeypatch.setattr(assessment_client, "check_remote", boom)

    response = session_client.post(
        f"/endpoints/{endpoint_id}/check",
        json={"username": "root", "auth_method": "password", "password": "wrong"},
    )

    assert response.status_code == 401


def test_check_endpoint_requires_auth():
    anonymous = TestClient(main.app)

    response = anonymous.post(
        "/endpoints/1/check",
        json={"username": "root", "auth_method": "password", "password": "hunter2"},
    )

    assert response.status_code == 401


def _assert_marker_absent_from_table(conn, table, marker):
    """Generic scan: every column of every row in `table`, stringified,
    must not contain `marker`. Doesn't need updating if columns are added
    later -- SELECT * picks them up automatically.
    """
    with conn.cursor() as cur:
        cur.execute(f"SELECT * FROM {table}")
        rows = cur.fetchall()
    for row in rows:
        for value in row:
            assert marker not in str(value), f"found marker in {table}: {value!r}"


def test_submitted_credentials_never_persisted_to_db(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    monkeypatch.setattr(assessment_client, "run_assessment_remote", lambda **kwargs: _FAKE_RUN)
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: _FAKE_CONTROL)

    marker = "SUPER-SECRET-MARKER-XYZ-DO-NOT-LEAK"
    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": marker},
    )
    assert response.status_code == 200

    conn = db.connect()
    _assert_marker_absent_from_table(conn, "endpoints", marker)
    _assert_marker_absent_from_table(conn, "discovery_results", marker)
    _assert_marker_absent_from_table(conn, "assessment_summaries", marker)
    conn.close()


def test_submitted_credentials_never_in_response_body(session_client, monkeypatch):
    endpoint_id = session_client.post("/endpoints", json={"address": "10.0.0.5"}).json()["id"]
    _discover_endpoint(session_client, monkeypatch, endpoint_id)

    monkeypatch.setattr(assessment_client, "run_assessment_remote", lambda **kwargs: _FAKE_RUN)
    monkeypatch.setattr(db, "select_control_by_title", lambda conn, *, document, titles: _FAKE_CONTROL)

    marker = "SUPER-SECRET-MARKER-XYZ-DO-NOT-LEAK"
    response = session_client.post(
        f"/endpoints/{endpoint_id}/assess",
        json={"username": "root", "auth_method": "password", "password": marker},
    )

    assert response.status_code == 200
    assert marker not in response.text
