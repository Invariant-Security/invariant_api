"""Orchestrates invariant_ingestion (fetch/extract/normalize) + Postgres
persistence -- ports cli/fetch.py's `fetch()` (partial: the raw-artifact
save already happens inside invariant_ingestion's own /ingestion/fetch),
cli/extract.py's `extract()`, and cli/import_document.py's
`import_document()`, minus their direct extractor/normalizer calls
(replaced by ingestion_client HTTP calls) but with the exact same
db.upsert_*/select_* sequence, unchanged.
"""

import httpx
from fastapi import APIRouter, HTTPException

from invariant_api.clients import ingestion_client
from invariant_api.storage import postgres as db

router = APIRouter()


@router.post("/ingest/fetch/{document}")
def fetch(document: str) -> dict:
    try:
        return ingestion_client.fetch(document)
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text) from e


@router.post("/ingest/extract/{document}")
def extract(document: str) -> dict:
    try:
        result = ingestion_client.extract(document)
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text) from e

    metadata = result["metadata"]
    conn = db.connect()
    source_id = db.upsert_source(
        conn, name=metadata["source"], type="benchmark_publisher", base_url="https://www.cisecurity.org"
    )
    document_id = db.upsert_document(
        conn, source_id=source_id, name=metadata["document"], document_type="benchmark"
    )
    version_id = db.upsert_document_version(
        conn,
        document_id=document_id,
        publisher_version=metadata["version"],
        content_hash=metadata["content_hash"],
        retrieved_at=metadata["retrieved_at"],
        raw_artifact_path=metadata["path"],
    )

    item_ids = []
    for rec in result["recommendations"]:
        raw_data = {k: v for k, v in rec.items() if k not in ("external_id", "title", "description")}
        item_id = db.upsert_extracted_item(
            conn,
            document_version_id=version_id,
            external_id=rec["external_id"],
            title=rec["title"],
            description=rec["description"],
            category=None,
            raw_data=raw_data,
        )
        item_ids.append(item_id)
    conn.commit()
    conn.close()
    return {"document_version_id": version_id, "extracted_item_ids": item_ids}


@router.post("/ingest/normalize/{document}")
def normalize(document: str) -> dict:
    conn = db.connect()
    version_id = db.select_latest_document_version_id(conn, source="cis", document=document)
    if version_id is None:
        conn.close()
        raise HTTPException(
            422, f"no document_version found for cis/{document} -- call /ingest/extract/{document} first"
        )

    extracted_items = db.select_extracted_items(conn, document_version_id=version_id)
    items = [
        {
            "external_id": item["external_id"],
            "title": item["title"],
            "description": item["description"] or "",
            "scored": item["raw_data"]["scored"],
            "profile_applicability": item["raw_data"]["profile_applicability"],
            "rationale": item["raw_data"]["rationale"],
            "audit": item["raw_data"]["audit"],
            "remediation": item["raw_data"]["remediation"],
        }
        for item in extracted_items
    ]

    try:
        controls = ingestion_client.normalize(items)
    except httpx.HTTPStatusError as e:
        conn.close()
        raise HTTPException(e.response.status_code, e.response.text) from e

    control_ids = []
    for control in controls:
        normalized_data = {k: v for k, v in control.items() if k not in ("external_id", "title", "description")}
        control_id = db.upsert_control(
            conn,
            document_version_id=version_id,
            external_id=control["external_id"],
            title=control["title"],
            description=control["description"],
            category=None,
            normalized_data=normalized_data,
        )
        control_ids.append(control_id)
    conn.commit()
    conn.close()
    return {"document_version_id": version_id, "control_ids": control_ids}
