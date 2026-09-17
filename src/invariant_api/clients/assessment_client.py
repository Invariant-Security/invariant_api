"""httpx client for invariant_assessment's one real endpoint. Base URL is
env-driven (INVARIANT_ASSESSMENT_URL) so this works both against the
docker-compose service name ("http://assessment:8000", the default) and a
locally-run instance during development.
"""

import os

import httpx

BASE_URL = os.environ.get("INVARIANT_ASSESSMENT_URL", "http://assessment:8000")


def list_containers() -> list[dict]:
    """Returns [{"name": str, "image": str, "id": str}, ...] -- every
    container this host's Docker socket can see, candidates for
    run_assessment()'s `target`. `id` is the full (non-truncated)
    Docker container ID -- routes/demo_snapshot.py uses it as the
    stable key for the public demo's alias mapping. See
    invariant_assessment's api.py for the exact response_model.
    """
    resp = httpx.get(f"{BASE_URL}/assessment/containers", timeout=10)
    resp.raise_for_status()
    return resp.json()


def check_target(target: str) -> dict:
    """Returns {"testable": bool, "os_id": str|None, "os_version_id":
    str|None, "family": str|None, "reason_code": str|None, "reason":
    str|None} -- see invariant_assessment's api.py for the exact
    response_model. Cheap pre-flight for run_assessment()'s `target`.
    """
    resp = httpx.post(f"{BASE_URL}/assessment/check", params={"target": target}, timeout=10)
    resp.raise_for_status()
    return resp.json()


def run_assessment(target: str) -> dict:
    """Returns {"document": str, "results": [{"titles": [...], "status":
    "PASS"|"FAIL", "evidence": str}, ...]} -- see invariant_assessment's
    api.py for the exact response_model.
    """
    resp = httpx.post(f"{BASE_URL}/assessment/run", params={"target": target}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def check_remote(
    *,
    host: str,
    port: int,
    username: str,
    auth_method: str,
    key_material: str | None = None,
    password: str | None = None,
) -> dict:
    """SSH twin of check_target() -- same cheap pre-flight, reached over
    SSH instead of docker exec. See invariant_assessment's api.py for the
    exact response_model (CheckResponse, now including `hostname`).
    """
    resp = httpx.post(
        f"{BASE_URL}/assessment/check-remote",
        json={
            "host": host,
            "port": port,
            "username": username,
            "auth_method": auth_method,
            "key_material": key_material,
            "password": password,
        },
        timeout=10,
    )
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
