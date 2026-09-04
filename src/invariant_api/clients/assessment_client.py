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


def run_assessment_remote(
    *,
    host: str,
    port: int,
    username: str,
    auth_method: str,
    key_material: str | None = None,
    password: str | None = None,
) -> dict:
    """Same response shape as run_assessment() -- reached over SSH
    instead of docker exec. Credential fields are forwarded exactly once
    in this request body and never stored on this client or logged --
    httpx does not log request bodies by default and this function does
    nothing to change that.
    """
    resp = httpx.post(
        f"{BASE_URL}/assessment/run-remote",
        json={
            "host": host,
            "port": port,
            "username": username,
            "auth_method": auth_method,
            "key_material": key_material,
            "password": password,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()
