"""Ported from the monolith's src/invariant/api/main.py -- same 3
read-only routes over what demo.sh writes to data/demo/, same external
contract (paths, status codes, response shapes unchanged). Only the
wiring changed: this is now a router mounted on invariant_api's own
FastAPI app instead of being the whole app.
"""

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter()

# parents[3] only resolves to the repo root for an editable install (pip
# install -e ., used in dev/CI) -- `pip install .` (the Dockerfile) copies
# demo.py into site-packages, breaking that assumption (same issue as
# storage/postgres.py's _SQL_DIR). INVARIANT_API_DATA_DEMO_DIR overrides it
# for that case (set to /app/data/demo in the Dockerfile).
DEMO_DATA_DIR = Path(os.environ.get("INVARIANT_API_DATA_DEMO_DIR") or Path(__file__).resolve().parents[3] / "data" / "demo")
STATUS_PATH = DEMO_DATA_DIR / "status.json"
RUNS_PATH = DEMO_DATA_DIR / "runs.jsonl"


def _read_runs() -> list[dict]:
    if not RUNS_PATH.exists():
        return []
    runs = []
    with open(RUNS_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            runs.append(json.loads(line))
    return runs


# ponytail: 2MB is ~6x today's average run line (~313KB, 73 runs / 22MB
# total) -- comfortable headroom without reading the whole file. If a
# single run ever legitimately exceeds this, the fallback below still
# returns the right answer, just slower; raise this constant first if that
# starts happening often.
_TAIL_READ_BYTES = 2 * 1024 * 1024


def _read_last_run() -> dict | None:
    """Like _read_runs()[-1], but reads only the tail of the file instead
    of parsing every line -- this is what made the demo page's first paint
    depend on downloading+parsing the entire (currently 22MB) runs.jsonl
    just to show the latest result.
    """
    if not RUNS_PATH.exists():
        return None
    file_size = RUNS_PATH.stat().st_size
    if file_size == 0:
        return None
    with open(RUNS_PATH, "rb") as f:
        f.seek(max(0, file_size - _TAIL_READ_BYTES))
        tail = f.read()
    lines = [line for line in tail.split(b"\n") if line.strip()]
    if lines:
        try:
            return json.loads(lines[-1])
        except json.JSONDecodeError:
            # The window landed mid-line (the real last line is bigger
            # than _TAIL_READ_BYTES, e.g. a run with 80+ findings whose
            # remediation text alone pushes it past 2MB -- confirmed on
            # the "pivot" host target, 2026-08-30) -- what we grabbed is a
            # truncated fragment, not a full line, even though it's
            # non-blank. Falls through to the full read below.
            pass
    if file_size > _TAIL_READ_BYTES:
        # Last line is bigger than our tail window -- fall back to a full
        # read rather than guess.
        runs = _read_runs()
        return runs[-1] if runs else None
    return None


@router.get("/api/demo/status")
def get_status():
    if not STATUS_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="No demo run has started yet -- run ./demo.sh first.",
        )
    return json.loads(STATUS_PATH.read_text())


@router.get("/api/demo/runs")
def get_runs():
    return list(reversed(_read_runs()))


@router.get("/api/demo/runs/latest")
def get_latest_run():
    run = _read_last_run()
    if run is None:
        raise HTTPException(
            status_code=404,
            detail="No completed demo run yet -- run ./demo.sh first.",
        )
    return run
