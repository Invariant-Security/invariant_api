"""httpx client for invariant_assessment's one real endpoint. Base URL is
env-driven (INVARIANT_ASSESSMENT_URL) so this works both against the
docker-compose service name ("http://assessment:8000", the default) and a
locally-run instance during development.
"""

import os

import httpx

BASE_URL = os.environ.get("INVARIANT_ASSESSMENT_URL", "http://assessment:8000")


def run_assessment(target: str) -> dict:
    """Returns {"document": str, "results": [{"titles": [...], "status":
    "PASS"|"FAIL", "evidence": str}, ...]} -- see invariant_assessment's
    api.py for the exact response_model.
    """
    resp = httpx.post(f"{BASE_URL}/assessment/run", params={"target": target}, timeout=30)
    resp.raise_for_status()
    return resp.json()
