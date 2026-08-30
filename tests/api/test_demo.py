"""Regression test for _read_last_run()'s tail-read fallback -- a run
line bigger than _TAIL_READ_BYTES used to 500 (json.loads on a truncated
mid-line fragment) instead of falling back to a full read. Confirmed live
in prod, 2026-08-30, once a run's findings pushed one line past 2MB.
"""

import json

from invariant_api.routes import demo


def test_read_last_run_falls_back_when_line_exceeds_tail_window(tmp_path, monkeypatch):
    monkeypatch.setattr(demo, "RUNS_PATH", tmp_path / "runs.jsonl")
    monkeypatch.setattr(demo, "_TAIL_READ_BYTES", 64)  # smaller than the line below

    run = {"run_id": "big-run", "padding": "x" * 500}
    demo.RUNS_PATH.write_text(json.dumps(run) + "\n")

    assert demo._read_last_run() == run
