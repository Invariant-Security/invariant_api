"""P3/C4: the public /api/demo/runs[/latest] endpoints must serve Demo Lab
targets only. runs.jsonl also held runs against the prod host ("pivot"),
real prod containers ("tamois") and 10.42.0.x addresses of unconfirmed
origin, and both endpoints returned them as is. Real HTTP through the app,
the filter isn't mocked.
"""

import json

from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.routes import demo

client = TestClient(main.app)

LEAKS = ("pivot", "tamois", "10.42.")


def _container(unexplained: int) -> dict:
    return {"fail_count": unexplained, "pass_count": 1, "total_findings": unexplained + 1,
            "environmental": [], "unexplained": [{"rule": f"r{i}"} for i in range(unexplained)], "story": "s"}


DEMO_ONLY = {"run_id": "demo-only", "started_at": "2026-08-28T00:00:00Z", "total_duration_seconds": 1.0,
             "report": {"targets": ["invariant-demo-debian-1"],
                        "containers": {"invariant-demo-debian-1": _container(1)}, "unexplained_total": 1}}
MIXED = {"run_id": "mixed", "started_at": "2026-08-30T00:00:00Z", "total_duration_seconds": 2.0,
         "report": {"targets": ["invariant-demo-x", "pivot", "tamois"],
                    "containers": {"invariant-demo-x": _container(2), "pivot": _container(5), "tamois": _container(7)},
                    "unexplained_total": 14, "is_demo": False}}
REAL_ONLY = {"run_id": "real-only", "started_at": "2026-08-31T00:00:00Z", "total_duration_seconds": 3.0,
             "report": {"targets": ["10.42.0.10"], "containers": {"10.42.0.10": _container(3)}, "is_demo": False}}


def _write_runs(tmp_path, monkeypatch, *runs):
    path = tmp_path / "runs.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in runs))
    monkeypatch.setattr(demo, "RUNS_PATH", path)


def _assert_no_leak(run):
    names = run["report"]["targets"] + list(run["report"]["containers"])
    assert not [n for n in names if n.startswith(LEAKS)], names


def test_runs_serves_demo_lab_targets_only(tmp_path, monkeypatch):
    _write_runs(tmp_path, monkeypatch, DEMO_ONLY, MIXED, REAL_ONLY)

    response = client.get("/api/demo/runs")

    assert response.status_code == 200
    body = response.json()
    assert [r["run_id"] for r in body] == ["mixed", "demo-only"]  # newest first, real-only dropped
    for run in body:
        _assert_no_leak(run)
    mixed = body[0]
    assert mixed["report"]["targets"] == ["invariant-demo-x"]
    assert mixed["report"]["containers"] == {"invariant-demo-x": _container(2)}
    assert mixed["report"]["unexplained_total"] == 2  # not 14: dropped targets don't leak via the aggregate
    # shape unchanged: same keys at run and report level
    assert set(mixed) == set(MIXED)
    assert set(mixed["report"]) == set(MIXED["report"])
    assert body[1] == DEMO_ONLY


def test_latest_skips_runs_with_no_demo_lab_target(tmp_path, monkeypatch):
    _write_runs(tmp_path, monkeypatch, DEMO_ONLY, MIXED, REAL_ONLY)

    response = client.get("/api/demo/runs/latest")

    assert response.status_code == 200
    run = response.json()
    assert run["run_id"] == "mixed"
    _assert_no_leak(run)
    assert set(run) == set(MIXED)


def test_latest_404_when_no_run_has_a_demo_lab_target(tmp_path, monkeypatch):
    _write_runs(tmp_path, monkeypatch, REAL_ONLY)

    assert client.get("/api/demo/runs").json() == []
    response = client.get("/api/demo/runs/latest")
    assert response.status_code == 404
    assert "demo.sh" in response.json()["detail"]


def test_prefix_must_match_at_start(tmp_path, monkeypatch):
    sneaky = {"run_id": "sneaky", "report": {"targets": ["prod-invariant-demo-x"],
                                             "containers": {"prod-invariant-demo-x": _container(0)}}}
    _write_runs(tmp_path, monkeypatch, sneaky)

    assert client.get("/api/demo/runs").json() == []
