"""POST/GET /demo-host-snapshot* -- hits a real Postgres (DATABASE_URL),
mirrors test_demo_snapshot.py's design exactly, adapted for hosts:
eligibility is a reserved IP range (`is_demo_endpoint`) instead of a
Docker label, and there's no `image` concept for a host.

Two distinct "real" fixtures on purpose: `_DEMO_*` is an Invariant Demo
Lab host (address inside the reserved 10.89.77.0/24 range -- eligible
to publish), `_BACKGROUND_REAL_*` is a real, non-demo endpoint that
just happens to also be registered (address outside that range, never
published) -- used to prove the leak scan still catches a genuinely
real identifier leaking into a demo host's evidence, without that
identifier being the thing being published.
"""

import psycopg
import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.auth import create_session_cookie
from invariant_api.clients import assessment_client
from invariant_api.demo_identities import DEMO_HOST_POOL
from invariant_api.storage import postgres as db

pytestmark = pytest.mark.integration

client = TestClient(main.app)
client.cookies.set("invariant_session", create_session_cookie("admin"))
anonymous = TestClient(main.app)

_DEMO_ADDRESS = "10.89.77.99"
_DEMO_LABEL = "demo-host-web-01"

_BACKGROUND_REAL_ADDRESS = "203.0.113.99"
_BACKGROUND_REAL_LABEL = "tamois-prod-db"


def _finding(**overrides) -> dict:
    base = {
        "target": _DEMO_LABEL,
        "external_id": "5.1.20",
        "status": "FAIL",
        "control_title": "Ensure sshd PermitRootLogin is disabled",
        "source_name": "cis",
        "document_name": "debian_linux_12",
        "document_version": "2.0.0",
        "evidence_output": "sshd_config: PermitRootLogin <not set>",
        "collected_at": "2026-09-17T00:00:00+00:00",
        "remediation": "Set PermitRootLogin to no.",
        "level": 1,
        "scored": True,
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def clean_tables():
    try:
        conn = db.connect()
    except (KeyError, psycopg.OperationalError) as exc:
        pytest.skip(f"no reachable DATABASE_URL configured: {exc}")
    with conn.cursor() as cur:
        cur.execute("DELETE FROM demo_host_snapshots")
        cur.execute("DELETE FROM demo_host_aliases")
        cur.execute("DELETE FROM endpoints")
    conn.commit()
    yield
    with conn.cursor() as cur:
        cur.execute("DELETE FROM demo_host_snapshots")
        cur.execute("DELETE FROM demo_host_aliases")
        cur.execute("DELETE FROM endpoints")
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def fake_live_containers(monkeypatch):
    """known_real_identifiers() is shared between the container and
    host demo flows -- it always iterates assessment_client.
    list_containers() too, even though this file is entirely about
    hosts. Without this, every test here would make a real HTTP call
    to the assessment service, unreachable from this test environment.
    Empty list is enough: no container-side identifiers are relevant
    to any test in this file.
    """
    monkeypatch.setattr(assessment_client, "list_containers", lambda: [])


@pytest.fixture(autouse=True)
def real_endpoints():
    """Registra os dois endpoints reais (demo-eligible e background)
    diretamente no banco -- a fonte de verdade pra elegibilidade é a
    faixa de IP em si (`is_demo_endpoint`), não algo mockável como o
    `assessment_client.list_containers()` monkeypatch dos containers.
    """
    conn = db.connect()
    demo_id = db.insert_endpoint(conn, address=_DEMO_ADDRESS, label=_DEMO_LABEL, tags=[])
    background_id = db.insert_endpoint(conn, address=_BACKGROUND_REAL_ADDRESS, label=_BACKGROUND_REAL_LABEL, tags=[])
    conn.commit()
    conn.close()
    return {"demo_id": demo_id, "background_id": background_id}


def _publish(endpoint_id=None, findings=None, real_endpoints_fixture=None):
    eid = endpoint_id if endpoint_id is not None else real_endpoints_fixture["demo_id"]
    return client.post(
        "/demo-host-snapshot/publish",
        json={"hosts": [{"endpoint_id": eid, "findings": findings or [_finding()]}]},
    )


def test_get_snapshot_with_no_publish_yet():
    response = anonymous.get("/demo-host-snapshot")

    assert response.status_code == 200
    assert response.json() == {"published_at": None, "hosts": []}
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate"


def test_preview_requires_admin_session():
    response = anonymous.post("/demo-host-snapshot/preview", json={"hosts": []})
    assert response.status_code == 401


def test_publish_requires_admin_session():
    response = anonymous.post("/demo-host-snapshot/publish", json={"hosts": []})
    assert response.status_code == 401


def test_revoke_requires_admin_session():
    response = anonymous.post("/demo-host-snapshot/revoke")
    assert response.status_code == 401


def test_publish_with_clean_payload_persists_and_sanitizes(real_endpoints):
    response = _publish(real_endpoints_fixture=real_endpoints)

    assert response.status_code == 200
    assert response.json() == {"status": "published"}

    snapshot = anonymous.get("/demo-host-snapshot").json()
    assert snapshot["published_at"] is not None
    assert len(snapshot["hosts"]) == 1
    host = snapshot["hosts"][0]
    assert host["name"] != _DEMO_LABEL
    assert host["address"] != _DEMO_ADDRESS
    assert host["findings"][0]["target"] == host["name"]


def test_publish_rejects_endpoint_id_not_found():
    response = _publish(endpoint_id=999999)

    assert response.status_code == 422
    assert "999999" in response.json()["detail"]["unverified_endpoint_ids"]
    assert anonymous.get("/demo-host-snapshot").json()["hosts"] == []


def test_publish_rejects_real_endpoint_outside_reserved_range(real_endpoints):
    """address fora de 10.89.77.0/24 nunca é publicável, mesmo com
    findings/evidence 100% limpos -- é o teste mais importante do
    módulo: elegibilidade é a faixa de IP, não a boa vontade do
    admin.
    """
    response = _publish(
        endpoint_id=real_endpoints["background_id"],
        findings=[_finding(evidence_output="clean, generic evidence")],
    )

    assert response.status_code == 422
    body = response.json()["detail"]
    assert str(real_endpoints["background_id"]) in body["not_demo_endpoint_ids"]
    assert anonymous.get("/demo-host-snapshot").json()["hosts"] == []


def test_preview_reports_not_demo_endpoint_ids_without_raising(real_endpoints):
    response = client.post(
        "/demo-host-snapshot/preview",
        json={"hosts": [{"endpoint_id": real_endpoints["background_id"], "findings": [_finding()]}]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert str(real_endpoints["background_id"]) in body["not_demo_endpoint_ids"]


def test_known_real_identifiers_excludes_demo_labeled_endpoints(real_endpoints):
    """demo_sanitize.known_real_identifiers() pula endpoints dentro da
    faixa reservada -- um host do Demo Lab é seguro de expor por
    definição, então seu próprio endereço/label real nunca deveria
    virar um "identificador a proteger" que bloqueia a própria
    publicação.
    """
    response = _publish(
        real_endpoints_fixture=real_endpoints,
        findings=[_finding(evidence_output=f"target host is {_DEMO_LABEL} at {_DEMO_ADDRESS}")],
    )

    assert response.status_code == 200

    # E a evidência publicada não deve mais citar o nome/endereço real
    # -- prova que o redact_real_identity + verify_redaction rodaram.
    snapshot = anonymous.get("/demo-host-snapshot").json()
    evidence = snapshot["hosts"][0]["findings"][0]["evidence_output"]
    assert _DEMO_LABEL not in evidence
    assert _DEMO_ADDRESS not in evidence


def test_leak_scan_blocks_real_endpoint_address(real_endpoints):
    """Defesa em profundidade: mesmo publicando um host demo de
    verdade, se a evidência citar o endereço de um endpoint REAL
    (não-demo) já cadastrado, a publicação continua bloqueada."""
    response = _publish(
        real_endpoints_fixture=real_endpoints,
        findings=[_finding(evidence_output=f"connection attempt from {_BACKGROUND_REAL_ADDRESS}")],
    )

    assert response.status_code == 422
    issues = response.json()["detail"]["issues"]
    assert any(i["category"] == "endpoint_address" for i in issues)
    assert anonymous.get("/demo-host-snapshot").json()["hosts"] == []


def test_leak_scan_blocks_real_endpoint_label(real_endpoints):
    response = _publish(
        real_endpoints_fixture=real_endpoints,
        findings=[_finding(evidence_output=f"discovered via {_BACKGROUND_REAL_LABEL}")],
    )

    assert response.status_code == 422
    issues = response.json()["detail"]["issues"]
    assert any(i["category"] == "endpoint_label" for i in issues)


def test_leak_scan_blocks_known_internal_domain(real_endpoints):
    response = _publish(
        real_endpoints_fixture=real_endpoints,
        findings=[_finding(evidence_output="callback URL points to invariantsec.org")],
    )

    assert response.status_code == 422
    issues = response.json()["detail"]["issues"]
    assert any(i["category"] == "internal_domain" for i in issues)


def test_alias_is_stable_across_publishes(real_endpoints):
    first = _publish(real_endpoints_fixture=real_endpoints)
    assert first.status_code == 200
    first_alias = anonymous.get("/demo-host-snapshot").json()["hosts"][0]["name"]

    second = _publish(real_endpoints_fixture=real_endpoints, findings=[_finding(evidence_output="second publish")])
    assert second.status_code == 200
    second_alias = anonymous.get("/demo-host-snapshot").json()["hosts"][0]["name"]

    assert first_alias == second_alias


def test_alias_reserved_in_preview_is_reused_in_publish(real_endpoints):
    preview_response = client.post(
        "/demo-host-snapshot/preview",
        json={"hosts": [{"endpoint_id": real_endpoints["demo_id"], "findings": [_finding()]}]},
    )
    assert preview_response.status_code == 200
    preview_alias = preview_response.json()["hosts"][0]["name"]

    assert anonymous.get("/demo-host-snapshot").json()["hosts"] == []

    publish_response = _publish(real_endpoints_fixture=real_endpoints)
    assert publish_response.status_code == 200
    published_alias = anonymous.get("/demo-host-snapshot").json()["hosts"][0]["name"]

    assert preview_alias == published_alias


def test_alias_pool_exhaustion_falls_back_to_numbered_alias(real_endpoints):
    conn = db.connect()
    for i, (label, address) in enumerate(DEMO_HOST_POOL):
        placeholder_id = db.insert_endpoint(conn, address=f"10.89.77.{200 + i}", label=None, tags=[])
        db.insert_demo_host_alias(conn, endpoint_id=placeholder_id, alias_label=label, alias_address=address)
    conn.commit()
    conn.close()

    response = _publish(real_endpoints_fixture=real_endpoints)

    assert response.status_code == 200
    alias_name = anonymous.get("/demo-host-snapshot").json()["hosts"][0]["name"]
    assert alias_name.startswith("extra-host-")


def test_two_publishes_get_returns_only_latest(real_endpoints):
    _publish(real_endpoints_fixture=real_endpoints)
    first_alias = anonymous.get("/demo-host-snapshot").json()["hosts"][0]["name"]

    _publish(real_endpoints_fixture=real_endpoints, findings=[_finding(evidence_output="second publish")])
    snapshot = anonymous.get("/demo-host-snapshot").json()
    assert len(snapshot["hosts"]) == 1
    assert snapshot["hosts"][0]["name"] == first_alias
    assert snapshot["hosts"][0]["findings"][0]["evidence_output"] == "second publish"


def test_revoke_clears_public_snapshot(real_endpoints):
    _publish(real_endpoints_fixture=real_endpoints)
    assert anonymous.get("/demo-host-snapshot").json()["hosts"] != []

    revoke_response = client.post("/demo-host-snapshot/revoke")
    assert revoke_response.status_code == 200
    assert revoke_response.json() == {"status": "revoked"}

    assert anonymous.get("/demo-host-snapshot").json() == {"published_at": None, "hosts": []}


def test_revoke_with_nothing_active_reports_nothing_to_revoke():
    response = client.post("/demo-host-snapshot/revoke")

    assert response.status_code == 200
    assert response.json() == {"status": "nothing_to_revoke"}


def test_report_ceo_by_target_returns_pdf(real_endpoints):
    _publish(real_endpoints_fixture=real_endpoints)
    alias_name = anonymous.get("/demo-host-snapshot").json()["hosts"][0]["name"]

    response = anonymous.get(f"/demo-host-snapshot/report?kind=ceo&target={alias_name}")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate"


def test_report_technical_by_target_returns_pdf(real_endpoints):
    _publish(real_endpoints_fixture=real_endpoints)
    alias_name = anonymous.get("/demo-host-snapshot").json()["hosts"][0]["name"]

    response = anonymous.get(f"/demo-host-snapshot/report?kind=technical&target={alias_name}")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")


def test_report_consolidated_ignores_target(real_endpoints):
    _publish(real_endpoints_fixture=real_endpoints)

    response = anonymous.get("/demo-host-snapshot/report?kind=consolidated")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")


def test_report_ceo_without_target_returns_422(real_endpoints):
    _publish(real_endpoints_fixture=real_endpoints)

    response = anonymous.get("/demo-host-snapshot/report?kind=ceo")

    assert response.status_code == 422


def test_report_with_unknown_target_returns_404(real_endpoints):
    _publish(real_endpoints_fixture=real_endpoints)

    response = anonymous.get("/demo-host-snapshot/report?kind=ceo&target=does-not-exist")

    assert response.status_code == 404


def test_report_with_no_snapshot_returns_404():
    response = anonymous.get("/demo-host-snapshot/report?kind=consolidated")

    assert response.status_code == 404
