"""Segredos obrigatórios do api: sem qualquer um, o processo não sobe e a
sessão não é assinada -- não existe valor de fallback."""

import os
import subprocess
import sys

import pytest

from invariant_api import auth, main

REQUIRED = main.REQUIRED_SECRETS


def test_required_secrets_are_the_four_separate_ones():
    assert set(REQUIRED) == {
        "INVARIANT_API_SECRET_KEY",
        "INVARIANT_INTERNAL_ASSESSMENT_TOKEN",
        "INVARIANT_INTERNAL_DISCOVERY_TOKEN",
        "INVARIANT_INTERNAL_INGESTION_TOKEN",
    }


@pytest.mark.parametrize("missing", REQUIRED)
def test_require_secrets_names_what_is_missing(monkeypatch, missing):
    for name in REQUIRED:
        monkeypatch.setenv(name, "valor-qualquer")
    monkeypatch.setenv(missing, "")
    with pytest.raises(RuntimeError, match=missing):
        main.require_secrets()


def test_session_secret_has_no_fallback(monkeypatch):
    monkeypatch.setenv("INVARIANT_API_SECRET_KEY", "")
    with pytest.raises(RuntimeError, match="INVARIANT_API_SECRET_KEY"):
        auth.create_session_cookie("admin")


@pytest.mark.parametrize("missing", REQUIRED)
def test_process_does_not_start_without_secret(missing):
    # Variável presente e vazia: o load_dotenv do api nunca sobrescreve o
    # ambiente, então nem um .env local consegue "salvar" o startup aqui.
    env = {**os.environ, **{name: "valor-qualquer" for name in REQUIRED}, missing: ""}
    proc = subprocess.run(
        [sys.executable, "-m", "uvicorn", "invariant_api.main:app", "--host", "127.0.0.1", "--port", "0"],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode != 0
    assert missing in proc.stderr
    assert "valor-qualquer" not in proc.stderr
