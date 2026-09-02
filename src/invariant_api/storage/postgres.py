"""Wires hand-written SQL (from sql/queries and sql/schema) to the
storage interfaces via psycopg.
"""

import os
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from invariant_api.config import load_dotenv

# parents[3] only resolves to the repo root for an editable install (pip
# install -e ., used in dev/CI) -- `pip install .` (the Dockerfile) copies
# postgres.py into site-packages, breaking that assumption. INVARIANT_API_SQL_DIR
# overrides it for that case (set to /app/sql in the Dockerfile).
_SQL_DIR = Path(os.environ.get("INVARIANT_API_SQL_DIR") or Path(__file__).resolve().parents[3] / "sql")
_QUERIES_DIR = _SQL_DIR / "queries"

_UPSERT_SOURCE = (_QUERIES_DIR / "upsert_source.sql").read_text()
_UPSERT_DOCUMENT = (_QUERIES_DIR / "upsert_document.sql").read_text()
_UPSERT_DOCUMENT_VERSION = (_QUERIES_DIR / "upsert_document_version.sql").read_text()
_UPSERT_EXTRACTED_ITEM = (_QUERIES_DIR / "upsert_extracted_item.sql").read_text()
_UPSERT_CONTROL = (_QUERIES_DIR / "upsert_control.sql").read_text()
_SELECT_LATEST_DOCUMENT_VERSION_ID = (_QUERIES_DIR / "select_latest_document_version_id.sql").read_text()
_SELECT_EXTRACTED_ITEMS = (_QUERIES_DIR / "select_extracted_items.sql").read_text()
_SELECT_CONTROL_BY_EXTERNAL_ID = (_QUERIES_DIR / "select_control_by_external_id.sql").read_text()
_SELECT_CONTROL_BY_TITLE = (_QUERIES_DIR / "select_control_by_title.sql").read_text()
_INSERT_CONTRACT = (_QUERIES_DIR / "insert_contract.sql").read_text()
_UPDATE_CONTRACT_MP_PAYMENT_ID = (_QUERIES_DIR / "update_contract_mp_payment_id.sql").read_text()
_UPDATE_CONTRACT_PAID = (_QUERIES_DIR / "update_contract_paid.sql").read_text()
_SELECT_CONTRACT_BY_ID = (_QUERIES_DIR / "select_contract_by_id.sql").read_text()
_INSERT_NEWSLETTER_SUBSCRIBER = (_QUERIES_DIR / "insert_newsletter_subscriber.sql").read_text()
_INSERT_ADMIN_USER = (_QUERIES_DIR / "insert_admin_user.sql").read_text()
_SELECT_ADMIN_USER_BY_USERNAME = (_QUERIES_DIR / "select_admin_user_by_username.sql").read_text()
_COUNT_ADMIN_USERS = (_QUERIES_DIR / "count_admin_users.sql").read_text()
_INSERT_ENDPOINT = (_QUERIES_DIR / "insert_endpoint.sql").read_text()
_SELECT_ENDPOINTS = (_QUERIES_DIR / "select_endpoints.sql").read_text()
_SELECT_ENDPOINT_BY_ID = (_QUERIES_DIR / "select_endpoint_by_id.sql").read_text()
_DELETE_ENDPOINT = (_QUERIES_DIR / "delete_endpoint.sql").read_text()
_INSERT_DISCOVERY_RESULT = (_QUERIES_DIR / "insert_discovery_result.sql").read_text()
_SELECT_LATEST_DISCOVERY_RESULTS_BY_ENDPOINT = (
    _QUERIES_DIR / "select_latest_discovery_results_by_endpoint.sql"
).read_text()


def connect() -> psycopg.Connection:
    """Open a connection using DATABASE_URL from .env / the environment."""
    load_dotenv()
    return psycopg.connect(os.environ["DATABASE_URL"])


def upsert_source(conn: psycopg.Connection, *, name: str, type: str, base_url: str | None = None) -> int:
    with conn.cursor() as cur:
        cur.execute(_UPSERT_SOURCE, {"name": name, "type": type, "base_url": base_url})
        return cur.fetchone()[0]


def upsert_document(conn: psycopg.Connection, *, source_id: int, name: str, document_type: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _UPSERT_DOCUMENT,
            {"source_id": source_id, "name": name, "document_type": document_type},
        )
        return cur.fetchone()[0]


def upsert_document_version(
    conn: psycopg.Connection,
    *,
    document_id: int,
    publisher_version: str,
    content_hash: str,
    retrieved_at: str,
    raw_artifact_path: str,
    parser_version: str | None = None,
    collector_version: str | None = None,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _UPSERT_DOCUMENT_VERSION,
            {
                "document_id": document_id,
                "publisher_version": publisher_version,
                "content_hash": content_hash,
                "retrieved_at": retrieved_at,
                "raw_artifact_path": raw_artifact_path,
                "parser_version": parser_version,
                "collector_version": collector_version,
            },
        )
        return cur.fetchone()[0]


def upsert_extracted_item(
    conn: psycopg.Connection,
    *,
    document_version_id: int,
    external_id: str,
    title: str,
    description: str | None,
    category: str | None,
    raw_data: dict,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _UPSERT_EXTRACTED_ITEM,
            {
                "document_version_id": document_version_id,
                "external_id": external_id,
                "title": title,
                "description": description,
                "category": category,
                "raw_data": Jsonb(raw_data),
            },
        )
        return cur.fetchone()[0]


def upsert_control(
    conn: psycopg.Connection,
    *,
    document_version_id: int,
    external_id: str,
    title: str,
    description: str | None,
    category: str | None,
    normalized_data: dict,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _UPSERT_CONTROL,
            {
                "document_version_id": document_version_id,
                "external_id": external_id,
                "title": title,
                "description": description,
                "category": category,
                "normalized_data": Jsonb(normalized_data),
            },
        )
        return cur.fetchone()[0]


def select_latest_document_version_id(conn: psycopg.Connection, *, source: str, document: str) -> int | None:
    with conn.cursor() as cur:
        cur.execute(_SELECT_LATEST_DOCUMENT_VERSION_ID, {"source": source, "document": document})
        row = cur.fetchone()
        return row[0] if row else None


def select_extracted_items(conn: psycopg.Connection, *, document_version_id: int) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(_SELECT_EXTRACTED_ITEMS, {"document_version_id": document_version_id})
        return [
            {"external_id": external_id, "title": title, "description": description, "raw_data": raw_data}
            for external_id, title, description, raw_data in cur.fetchall()
        ]


def select_control_by_external_id(conn: psycopg.Connection, *, document: str, external_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(_SELECT_CONTROL_BY_EXTERNAL_ID, {"document": document, "external_id": external_id})
        row = cur.fetchone()
        if row is None:
            return None
        title, normalized_data, source_name, document_name, publisher_version = row
        return {
            "title": title,
            "normalized_data": normalized_data,
            "source_name": source_name,
            "document_name": document_name,
            "publisher_version": publisher_version,
        }


def select_control_by_title(conn: psycopg.Connection, *, document: str, titles: list[str]) -> dict | None:
    """Looks up a control by one of several known title variants -- exact
    title wording drifts a little between CIS documents (confirmed:
    "Ensure permissions on /etc/shadow are configured" vs "Ensure access to
    /etc/shadow is configured" for the same underlying check), so callers
    pass every variant they know about rather than relying on one exact
    string or a stable external_id (also confirmed to drift between
    documents).
    """
    with conn.cursor() as cur:
        cur.execute(_SELECT_CONTROL_BY_TITLE, {"document": document, "titles": titles})
        row = cur.fetchone()
        if row is None:
            return None
        (
            external_id,
            title,
            source_name,
            document_name,
            publisher_version,
            normalized_data,
            raw_artifact_path,
            content_hash,
            retrieved_at,
        ) = row
        return {
            "external_id": external_id,
            "title": title,
            "source_name": source_name,
            "document_name": document_name,
            "publisher_version": publisher_version,
            "normalized_data": normalized_data,
            "raw_artifact_path": raw_artifact_path,
            "content_hash": content_hash,
            "retrieved_at": retrieved_at,
        }


def insert_contract(
    conn: psycopg.Connection,
    *,
    plan: str,
    activations: int,
    amount_cents: int,
    contact_name: str,
    contact_email: str,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _INSERT_CONTRACT,
            {
                "plan": plan,
                "activations": activations,
                "amount_cents": amount_cents,
                "contact_name": contact_name,
                "contact_email": contact_email,
            },
        )
        return cur.fetchone()[0]


def update_contract_mp_payment_id(conn: psycopg.Connection, *, id: int, mp_payment_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute(_UPDATE_CONTRACT_MP_PAYMENT_ID, {"id": id, "mp_payment_id": mp_payment_id})


def update_contract_paid(conn: psycopg.Connection, *, id: int) -> bool:
    """Returns False if the contract was already paid (or doesn't exist) --
    the webhook can be delivered more than once for the same payment, so
    the caller uses this to stay idempotent.
    """
    with conn.cursor() as cur:
        cur.execute(_UPDATE_CONTRACT_PAID, {"id": id})
        return cur.rowcount > 0


def insert_newsletter_subscriber(conn: psycopg.Connection, *, email: str) -> int | None:
    """Returns None when the row already existed (ON CONFLICT DO NOTHING
    finds nothing to RETURNING) -- that's fine, re-subscribing succeeds
    silently rather than leaking "this email is already subscribed".
    """
    with conn.cursor() as cur:
        cur.execute(_INSERT_NEWSLETTER_SUBSCRIBER, {"email": email})
        row = cur.fetchone()
        return row[0] if row else None


def insert_admin_user(conn: psycopg.Connection, *, username: str, password_hash: str) -> int:
    with conn.cursor() as cur:
        cur.execute(_INSERT_ADMIN_USER, {"username": username, "password_hash": password_hash})
        return cur.fetchone()[0]


def select_admin_user_by_username(conn: psycopg.Connection, *, username: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(_SELECT_ADMIN_USER_BY_USERNAME, {"username": username})
        row = cur.fetchone()
        if row is None:
            return None
        id, username, password_hash = row
        return {"id": id, "username": username, "password_hash": password_hash}


def count_admin_users(conn: psycopg.Connection) -> int:
    with conn.cursor() as cur:
        cur.execute(_COUNT_ADMIN_USERS)
        return cur.fetchone()[0]


def insert_endpoint(
    conn: psycopg.Connection, *, address: str, label: str | None, tags: list[str]
) -> int:
    with conn.cursor() as cur:
        cur.execute(_INSERT_ENDPOINT, {"address": address, "label": label, "tags": tags})
        return cur.fetchone()[0]


def select_endpoints(conn: psycopg.Connection) -> list[dict]:
    """Um endpoint por linha, já com a classificação mais recente (ou None
    se nenhuma rodada de discovery rodou pra ele ainda) -- ver o JOIN
    LATERAL em select_endpoints.sql.
    """
    with conn.cursor() as cur:
        cur.execute(_SELECT_ENDPOINTS)
        return [
            {
                "id": id,
                "address": address,
                "label": label,
                "tags": tags,
                "created_at": created_at,
                "classification": classification,
                "confidence": confidence,
                "scanned_at": scanned_at,
            }
            for id, address, label, tags, created_at, classification, confidence, scanned_at in cur.fetchall()
        ]


def select_endpoint_by_id(conn: psycopg.Connection, *, id: int) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(_SELECT_ENDPOINT_BY_ID, {"id": id})
        row = cur.fetchone()
        if row is None:
            return None
        endpoint_id, address, label, tags, created_at = row
        return {"id": endpoint_id, "address": address, "label": label, "tags": tags, "created_at": created_at}


def delete_endpoint(conn: psycopg.Connection, *, id: int) -> bool:
    with conn.cursor() as cur:
        cur.execute(_DELETE_ENDPOINT, {"id": id})
        return cur.rowcount > 0


def insert_discovery_result(
    conn: psycopg.Connection,
    *,
    endpoint_id: int,
    ip: str,
    classification: str,
    confidence: float,
    evidence: dict,
    scanned_at: str,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _INSERT_DISCOVERY_RESULT,
            {
                "endpoint_id": endpoint_id,
                "ip": ip,
                "classification": classification,
                "confidence": confidence,
                "evidence": Jsonb(evidence),
                "scanned_at": scanned_at,
            },
        )
        return cur.fetchone()[0]


def select_latest_discovery_results_by_endpoint(conn: psycopg.Connection, *, endpoint_id: int) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(_SELECT_LATEST_DISCOVERY_RESULTS_BY_ENDPOINT, {"endpoint_id": endpoint_id})
        return [
            {
                "ip": ip,
                "classification": classification,
                "confidence": confidence,
                "evidence": evidence,
                "scanned_at": scanned_at,
            }
            for ip, classification, confidence, evidence, scanned_at in cur.fetchall()
        ]


def select_contract_by_id(conn: psycopg.Connection, *, id: int) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(_SELECT_CONTRACT_BY_ID, {"id": id})
        row = cur.fetchone()
        if row is None:
            return None
        (
            contract_id,
            plan,
            activations,
            amount_cents,
            status,
            contact_name,
            contact_email,
            created_at,
            paid_at,
        ) = row
        return {
            "id": contract_id,
            "plan": plan,
            "activations": activations,
            "amount_cents": amount_cents,
            "status": status,
            "contact_name": contact_name,
            "contact_email": contact_email,
            "created_at": created_at,
            "paid_at": paid_at,
        }
