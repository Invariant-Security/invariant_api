"""httpx client for invariant_discovery's one real endpoint -- mesmo
formato de assessment_client.py (base URL env-driven, timeout generoso
porque um range /24 pode levar dezenas de segundos pra escanear por
completo, ver invariant_discovery's probe.py).
"""

import os

import httpx

from invariant_api.clients.internal_auth import DISCOVERY_TOKEN_ENV, auth_headers

BASE_URL = os.environ.get("INVARIANT_DISCOVERY_URL", "http://discovery:8000")


def discover(addresses: list[str]) -> list[dict]:
    """Returns [{"ip": str, "classification": str, "confidence": float,
    "evidence": dict, "scanned_at": str}, ...] -- um item por IP, com
    ranges/CIDR já expandidos pelo lado do invariant_discovery. Ver
    invariant_discovery's api.py para o response_model exato.
    """
    resp = httpx.post(f"{BASE_URL}/discover", json={"addresses": addresses}, headers=auth_headers(DISCOVERY_TOKEN_ENV), timeout=120)
    resp.raise_for_status()
    return resp.json()["results"]
