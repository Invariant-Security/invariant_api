"""Semeia/limpa um documento CIS já extraído no Postgres de teste (o que
/ingest/extract deixaria gravado), para exercitar normalize sem rede."""

import psycopg
import pytest

from conftest import assert_test_database
from invariant_api.storage import postgres as db

SLUG = "ubuntu_linux_24_04"  # normalize usa o slug com "_"; fetch/extract, "cis-ubuntu-linux-24-04"
DOC = "cis-ubuntu-linux-24-04"


def connect_or_skip():
    try:
        conn = db.connect()
    except (KeyError, psycopg.OperationalError) as exc:
        pytest.skip(f"no reachable DATABASE_URL configured: {exc}")
    assert_test_database(conn)
    return conn


def clean(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM controls WHERE document_version_id IN (SELECT dv.id FROM document_versions dv JOIN documents d ON d.id = dv.document_id WHERE d.name = %s)", (SLUG,))
        cur.execute("DELETE FROM extracted_items WHERE document_version_id IN (SELECT dv.id FROM document_versions dv JOIN documents d ON d.id = dv.document_id WHERE d.name = %s)", (SLUG,))
        cur.execute("DELETE FROM document_versions WHERE document_id IN (SELECT id FROM documents WHERE name = %s)", (SLUG,))
        cur.execute("DELETE FROM documents WHERE name = %s", (SLUG,))
    conn.commit()


def seed(conn) -> int:
    source_id = db.upsert_source(conn, name="cis", type="benchmark_publisher")
    document_id = db.upsert_document(conn, source_id=source_id, name=SLUG, document_type="benchmark")
    version_id = db.upsert_document_version(
        conn, document_id=document_id, publisher_version="1.0.0", content_hash="seed",
        retrieved_at="2026-01-01T00:00:00+00:00", raw_artifact_path="/tmp/seed.pdf",
    )
    db.upsert_extracted_item(
        conn, document_version_id=version_id, external_id="1.1.1", title="Ensure test control", description="d",
        category=None,
        raw_data={"scored": True, "profile_applicability": ["Level 1 - Server"], "rationale": "r", "audit": "a", "remediation": "m"},
    )
    conn.commit()
    return version_id


def control_count(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM controls c JOIN document_versions dv ON dv.id = c.document_version_id JOIN documents d ON d.id = dv.document_id WHERE d.name = %s", (SLUG,))
        return cur.fetchone()[0]
