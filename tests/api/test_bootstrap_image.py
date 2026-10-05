"""Constrói a imagem do api (Dockerfile do repo) e roda
`python -m invariant_api.bootstrap_documents` DENTRO dela contra o Postgres
real: pega módulo no caminho errado ou arquivo que não entrou na imagem, que
o teste do script (docker falso) não vê. Container em --network host: alcança
o Postgres de teste e o ingestion real (uvicorn) em 127.0.0.1."""

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from live_server import live_server

import ingest_seed
from invariant_api.clients.internal_auth import INGESTION_TOKEN_ENV

ingestion_api = pytest.importorskip("invariant_ingestion.api")

ROOT = Path(__file__).resolve().parents[2]
pytestmark = [pytest.mark.integration, pytest.mark.skipif(shutil.which("docker") is None, reason="docker indisponível")]


@pytest.fixture(scope="module")
def image():
    tag = f"invariant-api-test:{uuid.uuid4().hex[:8]}"
    subprocess.run(["docker", "build", "-q", "-t", tag, str(ROOT)], check=True, timeout=900)
    yield tag
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)


@pytest.fixture
def conn():
    conn = ingest_seed.connect_or_skip()
    ingest_seed.clean(conn)
    yield conn
    ingest_seed.clean(conn)
    conn.close()


def _run(image, ingestion_url, *docs):
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "host",
         "-e", f"DATABASE_URL={os.environ['DATABASE_URL']}",
         "-e", f"INVARIANT_INGESTION_URL={ingestion_url}",
         "-e", f"{INGESTION_TOKEN_ENV}={os.environ[INGESTION_TOKEN_ENV]}",
         image, "python", "-m", "invariant_api.bootstrap_documents", *docs],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def test_seeded_document_is_skipped_and_controls_written_even_after_a_failing_one(image, conn):
    ingest_seed.seed(conn)
    with live_server(ingestion_api.app) as ingestion:
        # primeiro um documento que o ingestion real recusa (404, sem rede), depois o semeado
        out = _run(image, ingestion, "cis-nao-existe", ingest_seed.DOC)
    assert "AVISO: fetch de cis-nao-existe falhou" in out, out
    assert f"{ingest_seed.DOC} já ingerido" in out, out
    assert "Bootstrap de documentos concluído" in out
    assert ingest_seed.control_count(conn) == 1


def test_unreachable_ingestion_is_logged_per_document_and_never_crashes(image, conn):
    out = _run(image, "http://127.0.0.1:1", "cis-debian-linux-12", "cis-debian-linux-13")
    assert "AVISO: fetch de cis-debian-linux-12 falhou" in out, out
    assert "AVISO: fetch de cis-debian-linux-13 falhou" in out, out
    assert "ingerido com sucesso" not in out
    assert "Bootstrap de documentos concluído" in out
