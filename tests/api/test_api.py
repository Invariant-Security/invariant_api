"""Ported from the monolith's tests/api/test_api.py -- same assertions,
same external contract. Only difference: STATUS_PATH/RUNS_PATH now live
on invariant_api.routes.demo (a router), not on main itself, since
main.py stopped being "the whole app" and became an app that mounts
routers -- monkeypatch targets moved accordingly.
"""

import importlib
import json

from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.routes import demo

client = TestClient(main.app)


def test_get_status_404_when_no_run_has_started(tmp_path, monkeypatch):
    monkeypatch.setattr(demo, "STATUS_PATH", tmp_path / "status.json")

    response = client.get("/api/demo/status")

    assert response.status_code == 404
    assert "demo.sh" in response.json()["detail"]


def test_get_status_returns_status_json_contents(tmp_path, monkeypatch):
    status = {
        "run_id": "20260821T000000-1",
        "started_at": "2026-08-21T00:00:00Z",
        "current_step": "Applying database migrations (alembic upgrade head)",
        "finished": False,
        "completed_steps": [{"name": "Preflight checks", "duration_seconds": 0.4}],
    }
    status_path = tmp_path / "status.json"
    status_path.write_text(json.dumps(status))
    monkeypatch.setattr(demo, "STATUS_PATH", status_path)

    response = client.get("/api/demo/status")

    assert response.status_code == 200
    assert response.json() == status


def test_get_runs_empty_list_when_no_runs_file(tmp_path, monkeypatch):
    monkeypatch.setattr(demo, "RUNS_PATH", tmp_path / "runs.jsonl")

    response = client.get("/api/demo/runs")

    assert response.status_code == 200
    assert response.json() == []


def test_get_runs_returns_most_recent_first(tmp_path, monkeypatch):
    runs_path = tmp_path / "runs.jsonl"
    run_a = {"run_id": "a", "started_at": "2026-08-21T00:00:00Z", "total_duration_seconds": 10.0, "report": {}}
    run_b = {"run_id": "b", "started_at": "2026-08-21T01:00:00Z", "total_duration_seconds": 20.0, "report": {}}
    runs_path.write_text(json.dumps(run_a) + "\n" + json.dumps(run_b) + "\n")
    monkeypatch.setattr(demo, "RUNS_PATH", runs_path)

    response = client.get("/api/demo/runs")

    assert response.status_code == 200
    body = response.json()
    assert [r["run_id"] for r in body] == ["b", "a"]


def test_get_runs_skips_blank_lines(tmp_path, monkeypatch):
    runs_path = tmp_path / "runs.jsonl"
    run_a = {"run_id": "a", "report": {}}
    runs_path.write_text(json.dumps(run_a) + "\n\n")
    monkeypatch.setattr(demo, "RUNS_PATH", runs_path)

    response = client.get("/api/demo/runs")

    assert response.status_code == 200
    assert response.json() == [run_a]


def test_get_latest_run_404_when_no_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(demo, "RUNS_PATH", tmp_path / "runs.jsonl")

    response = client.get("/api/demo/runs/latest")

    assert response.status_code == 404
    assert "demo.sh" in response.json()["detail"]


def test_get_latest_run_returns_last_line_whole(tmp_path, monkeypatch):
    """Returns the whole run object (run_id/started_at/report/...), not
    just .report -- changed alongside the _read_last_run() tail-read
    optimization since nothing consumed the old .report-only shape yet.
    """
    runs_path = tmp_path / "runs.jsonl"
    run_a = {"run_id": "a", "report": {"containers": {"container-a": {"fail_count": 1}}}}
    run_b = {"run_id": "b", "report": {"containers": {"container-b": {"fail_count": 2}}}}
    runs_path.write_text(json.dumps(run_a) + "\n" + json.dumps(run_b) + "\n")
    monkeypatch.setattr(demo, "RUNS_PATH", runs_path)

    response = client.get("/api/demo/runs/latest")

    assert response.status_code == 200
    assert response.json() == run_b


def test_get_latest_run_skips_trailing_blank_line(tmp_path, monkeypatch):
    runs_path = tmp_path / "runs.jsonl"
    run_a = {"run_id": "a", "report": {}}
    runs_path.write_text(json.dumps(run_a) + "\n\n")
    monkeypatch.setattr(demo, "RUNS_PATH", runs_path)

    response = client.get("/api/demo/runs/latest")

    assert response.status_code == 200
    assert response.json() == run_a


def test_read_last_run_matches_full_read_without_parsing_earlier_lines(tmp_path, monkeypatch):
    """The actual perf fix: on a file much bigger than _TAIL_READ_BYTES,
    _read_last_run() must still return the true last line -- and must do
    it via the tail read, not by silently falling back to a full parse
    (which would defeat the whole point).
    """
    runs_path = tmp_path / "runs.jsonl"
    # Every line padded well past the tail window so a correct
    # implementation is forced to actually seek, not just happen to read
    # everything anyway.
    padding = "x" * 5000
    lines = [json.dumps({"run_id": f"run-{i}", "padding": padding, "report": {}}) for i in range(500)]
    runs_path.write_text("\n".join(lines) + "\n")

    monkeypatch.setattr(demo, "RUNS_PATH", runs_path)
    monkeypatch.setattr(demo, "_TAIL_READ_BYTES", 8192)  # force a real seek, not "tail happens to be everything"
    assert runs_path.stat().st_size > 8192 * 2

    read_runs_called = []
    original_read_runs = demo._read_runs

    def spy_read_runs():
        read_runs_called.append(True)
        return original_read_runs()

    monkeypatch.setattr(demo, "_read_runs", spy_read_runs)

    result = demo._read_last_run()

    assert result["run_id"] == "run-499"
    assert not read_runs_called, "should answer from the tail read, not fall back to a full parse"


def test_cors_allows_vite_dev_server_origin():
    response = client.options(
        "/api/demo/status",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_origins_configurable_via_env_var(monkeypatch):
    monkeypatch.setenv("INVARIANT_API_CORS_ORIGINS", "https://prod.example.com, https://staging.example.com")
    reloaded = importlib.reload(main)
    try:
        prod_client = TestClient(reloaded.app)

        allowed = prod_client.options(
            "/api/demo/status",
            headers={"Origin": "https://prod.example.com", "Access-Control-Request-Method": "GET"},
        )
        assert allowed.headers["access-control-allow-origin"] == "https://prod.example.com"

        dev_default = prod_client.options(
            "/api/demo/status",
            headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
        )
        assert "access-control-allow-origin" not in dev_default.headers
    finally:
        monkeypatch.delenv("INVARIANT_API_CORS_ORIGINS", raising=False)
        importlib.reload(main)
