"""POST/GET /demo-snapshot* -- hits a real Postgres (DATABASE_URL), same
discipline as test_endpoints.py. assessment_client.list_containers is
monkeypatched to control the "live" container list both the metadata
verification and the leak scan's known-identifiers use -- never mock
the leak scan itself, it's the thing under test.
"""

import psycopg
import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.auth import create_session_cookie
from invariant_api.clients import assessment_client
from invariant_api.demo_identities import DEMO_CONTAINER_POOL
from invariant_api.storage import postgres as db

pytestmark = pytest.mark.integration

client = TestClient(main.app)
client.cookies.set("invariant_session", create_session_cookie("admin"))
anonymous = TestClient(main.app)

_REAL_CONTAINER_ID = "a1b2c3d4e5f6realcontaineridfulllength"
_REAL_NAME = "tamois-ia-juridica-tamois"
_REAL_IMAGE = "ghcr.io/tamois-real-org/tamois:v1"


def _finding(**overrides) -> dict:
    base = {
        "target": _REAL_NAME,
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
        cur.execute("DELETE FROM demo_snapshots")
        cur.execute("DELETE FROM demo_container_aliases")
        cur.execute("DELETE FROM endpoints")
    conn.commit()
    yield
    with conn.cursor() as cur:
        cur.execute("DELETE FROM demo_snapshots")
        cur.execute("DELETE FROM demo_container_aliases")
        cur.execute("DELETE FROM endpoints")
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def fake_live_containers(monkeypatch):
    monkeypatch.setattr(
        assessment_client,
        "list_containers",
        lambda: [{"name": _REAL_NAME, "image": _REAL_IMAGE, "id": _REAL_CONTAINER_ID}],
    )


def _publish(container_id=_REAL_CONTAINER_ID, findings=None):
    return client.post(
        "/demo-snapshot/publish",
        json={"containers": [{"container_id": container_id, "findings": findings or [_finding()]}]},
    )


def test_get_snapshot_with_no_publish_yet():
    response = anonymous.get("/demo-snapshot")

    assert response.status_code == 200
    assert response.json() == {"published_at": None, "containers": []}
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate"


def test_preview_requires_admin_session():
    response = anonymous.post("/demo-snapshot/preview", json={"containers": []})
    assert response.status_code == 401


def test_publish_requires_admin_session():
    response = anonymous.post("/demo-snapshot/publish", json={"containers": []})
    assert response.status_code == 401


def test_revoke_requires_admin_session():
    response = anonymous.post("/demo-snapshot/revoke")
    assert response.status_code == 401


def test_publish_with_clean_payload_persists_and_sanitizes():
    response = _publish()

    assert response.status_code == 200
    assert response.json() == {"status": "published"}

    snapshot = anonymous.get("/demo-snapshot").json()
    assert snapshot["published_at"] is not None
    assert len(snapshot["containers"]) == 1
    container = snapshot["containers"][0]
    assert container["name"] != _REAL_NAME
    assert container["image"] != _REAL_IMAGE
    assert container["name"].startswith(("app-", "cache-", "queue-", "gateway-")) or "-" in container["name"]
    assert container["findings"][0]["target"] == container["name"]


def test_publish_rejects_container_id_not_in_live_list():
    response = _publish(container_id="does-not-exist-anywhere")

    assert response.status_code == 422
    assert "does-not-exist-anywhere" in response.json()["detail"]["unverified_container_ids"]
    assert anonymous.get("/demo-snapshot").json()["containers"] == []


def test_leak_scan_ignores_isolated_generic_terms():
    response = _publish(findings=[_finding(evidence_output="postgres is running as expected"), _finding(evidence_output="nginx config looks fine")])

    assert response.status_code == 200


def test_leak_scan_blocks_real_container_name():
    response = _publish(findings=[_finding(evidence_output=f"found reference to {_REAL_NAME} in config")])

    assert response.status_code == 422
    issues = response.json()["detail"]["issues"]
    assert any(i["category"] == "container_name" for i in issues)
    assert anonymous.get("/demo-snapshot").json()["containers"] == []


def test_leak_scan_blocks_distinctive_image_org():
    response = _publish(findings=[_finding(evidence_output="deployed from tamois-real-org registry")])

    assert response.status_code == 422
    issues = response.json()["detail"]["issues"]
    assert any(i["category"] == "container_image_org" for i in issues)


def test_leak_scan_blocks_full_real_image_string():
    response = _publish(findings=[_finding(remediation=f"rebuild image {_REAL_IMAGE} with the fix applied")])

    assert response.status_code == 422
    issues = response.json()["detail"]["issues"]
    assert any(i["category"] == "container_image" for i in issues)


def test_leak_scan_blocks_real_endpoint_ip():
    conn = db.connect()
    db.insert_endpoint(conn, address="10.20.30.40", label="prod-gateway", tags=[])
    conn.commit()
    conn.close()

    response = _publish(findings=[_finding(evidence_output="connection refused from 10.20.30.40")])

    assert response.status_code == 422
    issues = response.json()["detail"]["issues"]
    assert any(i["category"] == "endpoint_address" for i in issues)


def test_leak_scan_blocks_known_internal_domain():
    response = _publish(findings=[_finding(evidence_output="callback URL points to invariantsec.org")])

    assert response.status_code == 422
    issues = response.json()["detail"]["issues"]
    assert any(i["category"] == "internal_domain" for i in issues)


def test_alias_is_stable_across_publishes_even_if_real_name_changes(monkeypatch):
    first = _publish()
    assert first.status_code == 200
    first_alias = anonymous.get("/demo-snapshot").json()["containers"][0]["name"]

    # Mesmo container_id, nome real "mudou" -- alias tem que continuar o mesmo.
    monkeypatch.setattr(
        assessment_client,
        "list_containers",
        lambda: [{"name": "tamois-renamed", "image": _REAL_IMAGE, "id": _REAL_CONTAINER_ID}],
    )
    second = _publish()
    assert second.status_code == 200
    second_alias = anonymous.get("/demo-snapshot").json()["containers"][0]["name"]

    assert first_alias == second_alias


def test_alias_reserved_in_preview_is_reused_in_publish():
    preview_response = client.post(
        "/demo-snapshot/preview",
        json={"containers": [{"container_id": _REAL_CONTAINER_ID, "findings": [_finding()]}]},
    )
    assert preview_response.status_code == 200
    preview_alias = preview_response.json()["containers"][0]["name"]

    # Nada foi publicado ainda -- só o alias foi reservado.
    assert anonymous.get("/demo-snapshot").json()["containers"] == []

    publish_response = _publish()
    assert publish_response.status_code == 200
    published_alias = anonymous.get("/demo-snapshot").json()["containers"][0]["name"]

    assert preview_alias == published_alias


def test_alias_assignment_tolerates_unique_violation_race(monkeypatch):
    from invariant_api import demo_identities

    calls = {"n": 0}
    real_insert = db.insert_demo_alias

    def flaky_insert(conn, *, container_id, alias_name, alias_image):
        calls["n"] += 1
        if calls["n"] == 1:
            raise psycopg.errors.UniqueViolation("simulated race")
        return real_insert(conn, container_id=container_id, alias_name=alias_name, alias_image=alias_image)

    monkeypatch.setattr(demo_identities.db, "insert_demo_alias", flaky_insert)

    response = _publish()

    assert response.status_code == 200
    assert calls["n"] >= 2


def test_alias_pool_exhaustion_falls_back_to_numbered_alias():
    conn = db.connect()
    for i, (name, image) in enumerate(DEMO_CONTAINER_POOL):
        db.insert_demo_alias(conn, container_id=f"placeholder-{i}", alias_name=name, alias_image=image)
    conn.commit()
    conn.close()

    response = _publish()

    assert response.status_code == 200
    alias_name = anonymous.get("/demo-snapshot").json()["containers"][0]["name"]
    assert alias_name.startswith("extra-service-")


def test_two_publishes_get_returns_only_latest():
    _publish()
    first_alias = anonymous.get("/demo-snapshot").json()["containers"][0]["name"]

    _publish(findings=[_finding(evidence_output="second publish")])
    snapshot = anonymous.get("/demo-snapshot").json()
    assert len(snapshot["containers"]) == 1
    # mesmo alias (mesmo container_id) -- mas o conteúdo (findings) é o da 2a publicação
    assert snapshot["containers"][0]["name"] == first_alias
    assert snapshot["containers"][0]["findings"][0]["evidence_output"] == "second publish"


def test_revoke_clears_public_snapshot():
    _publish()
    assert anonymous.get("/demo-snapshot").json()["containers"] != []

    revoke_response = client.post("/demo-snapshot/revoke")
    assert revoke_response.status_code == 200
    assert revoke_response.json() == {"status": "revoked"}

    assert anonymous.get("/demo-snapshot").json() == {"published_at": None, "containers": []}


def test_revoke_with_nothing_active_reports_nothing_to_revoke():
    response = client.post("/demo-snapshot/revoke")

    assert response.status_code == 200
    assert response.json() == {"status": "nothing_to_revoke"}


def test_report_ceo_by_target_returns_pdf():
    _publish()
    alias_name = anonymous.get("/demo-snapshot").json()["containers"][0]["name"]

    response = anonymous.get(f"/demo-snapshot/report?kind=ceo&target={alias_name}")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate"


def test_report_technical_by_target_returns_pdf():
    _publish()
    alias_name = anonymous.get("/demo-snapshot").json()["containers"][0]["name"]

    response = anonymous.get(f"/demo-snapshot/report?kind=technical&target={alias_name}")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")


def test_report_consolidated_ignores_target():
    _publish()

    response = anonymous.get("/demo-snapshot/report?kind=consolidated")

    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")


def test_report_ceo_without_target_returns_422():
    _publish()

    response = anonymous.get("/demo-snapshot/report?kind=ceo")

    assert response.status_code == 422


def test_report_with_unknown_target_returns_404():
    _publish()

    response = anonymous.get("/demo-snapshot/report?kind=ceo&target=does-not-exist")

    assert response.status_code == 404


def test_report_with_no_snapshot_returns_404():
    response = anonymous.get("/demo-snapshot/report?kind=consolidated")

    assert response.status_code == 404


def test_report_unreachable_immediately_after_revoke():
    _publish()
    alias_name = anonymous.get("/demo-snapshot").json()["containers"][0]["name"]
    assert anonymous.get(f"/demo-snapshot/report?kind=ceo&target={alias_name}").status_code == 200

    client.post("/demo-snapshot/revoke")

    assert anonymous.get(f"/demo-snapshot/report?kind=ceo&target={alias_name}").status_code == 404
