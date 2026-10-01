"""bootstrap-documents.sh contra a borda real do appliance (nginx HTTPS com o
template do compose, na frente de um eco que responde 200 a tudo)."""

import os
import subprocess
from pathlib import Path

import pytest
from appliance_edge import appliance_edge, docker_available

SCRIPT = Path(__file__).resolve().parents[1] / "bootstrap-documents.sh"
DOCS = "cis-ubuntu-linux-24-04 cis-debian-linux-12"

pytestmark = pytest.mark.skipif(not docker_available(), reason="docker indisponível")


def _run(https_port: str) -> str:
    env = {**os.environ, "INVARIANT_HTTPS_PORT": https_port, "INVARIANT_BOOTSTRAP_DOCUMENTS": DOCS}
    proc = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=120)
    return proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def edge():
    with appliance_edge() as urls:
        yield urls


def test_bootstrap_talks_https_through_the_appliance_edge(edge):
    _, https_url, _ = edge
    out = _run(https_url.rsplit(":", 1)[1])
    for doc in DOCS.split():
        assert f"{doc} já ingerido" in out, out


def test_a_non_200_answer_never_counts_as_done(edge):
    # Porta 80 do appliance (só redireciona/healthz): nenhum passo pode ser
    # registrado como feito.
    http_url, _, _ = edge
    out = _run(http_url.rsplit(":", 1)[1])
    assert "já ingerido" not in out and "ingerido com sucesso" not in out, out
    assert out.count("AVISO") == len(DOCS.split()), out
