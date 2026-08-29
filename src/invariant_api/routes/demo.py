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
    runs = _read_runs()
    if not runs:
        raise HTTPException(
            status_code=404,
            detail="No completed demo run yet -- run ./demo.sh first.",
        )
    return runs[-1]["report"]
