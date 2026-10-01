"""httpx client for invariant_ingestion's 3 endpoints. Base URL is
env-driven (INVARIANT_INGESTION_URL), same pattern as assessment_client.
"""

import os

import httpx

from invariant_api.clients.internal_auth import INGESTION_TOKEN_ENV, auth_headers

BASE_URL = os.environ.get("INVARIANT_INGESTION_URL", "http://ingestion:8000")


def fetch(document: str) -> dict:
    """Returns the RawArtifact shape: {"source", "document", "version",
    "content_hash", "retrieved_at", "path"}.
    """
    resp = httpx.post(f"{BASE_URL}/ingestion/fetch/{document}", headers=auth_headers(INGESTION_TOKEN_ENV), timeout=60)
    resp.raise_for_status()
    return resp.json()


def extract(document: str) -> dict:
    """Returns {"metadata": RawArtifact, "recommendations": [ExtractedRecommendation, ...]}."""
    resp = httpx.post(f"{BASE_URL}/ingestion/extract/{document}", headers=auth_headers(INGESTION_TOKEN_ENV), timeout=60)
    resp.raise_for_status()
    return resp.json()


def normalize(items: list[dict]) -> list[dict]:
    """`items` are ExtractedRecommendation-shaped dicts (external_id, title,
    description, scored, profile_applicability, rationale, audit,
    remediation). Returns a list of Control-shaped dicts.
    """
    resp = httpx.post(f"{BASE_URL}/ingestion/normalize", json=items, headers=auth_headers(INGESTION_TOKEN_ENV), timeout=60)
    resp.raise_for_status()
    return resp.json()
