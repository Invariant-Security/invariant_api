"""bootstrap-documents.sh: resolve o compose pelo diretório do próprio script
(não pelo cwd) e roda a ingestão dentro do container api. O módulo em si é
coberto por tests/api/test_bootstrap_image.py (imagem real); aqui o `docker`
é um executável falso no PATH que grava os argumentos."""

import os
import subprocess
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "bootstrap-documents.sh"


def _run(tmp: Path, docker_body: str, **extra_env):
    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "docker"
    fake.write_text(f'#!/usr/bin/env bash\necho "$@" > "{tmp}/args"\n{docker_body}\n')
    fake.chmod(0o755)
    # script copiado pra "/opt/invariant" e chamado de um cwd qualquer, como install.sh faz
    opt = tmp / "opt"
    opt.mkdir()
    (opt / "bootstrap-documents.sh").write_bytes(SCRIPT.read_bytes())
    (opt / "bootstrap-documents.sh").chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in ("INVARIANT_BOOTSTRAP_DOCUMENTS", "INVARIANT_ENV_FILE")}
    env.update(PATH=f"{bin_dir}:{os.environ['PATH']}", **extra_env)
    other_cwd = tmp / "elsewhere"
    other_cwd.mkdir()
    proc = subprocess.run([str(opt / "bootstrap-documents.sh")], env=env, cwd=other_cwd, capture_output=True, text=True, timeout=30)
    return proc, (tmp / "args").read_text().strip(), opt


def test_runs_ingestion_inside_api_container_with_compose_from_script_dir():
    with tempfile.TemporaryDirectory() as t:
        proc, args, opt = _run(Path(t), "", INVARIANT_BOOTSTRAP_DOCUMENTS="cis-ubuntu-linux-24-04 cis-debian-linux-12")
    assert proc.returncode == 0, proc.stderr
    assert args == (
        f"compose -f {opt}/docker-compose.appliance.yml --env-file /etc/invariant/.env "
        "exec -T api python -m invariant_api.bootstrap_documents cis-ubuntu-linux-24-04 cis-debian-linux-12"
    )


def test_default_documents_and_env_file_override():
    with tempfile.TemporaryDirectory() as t:
        proc, args, _ = _run(Path(t), "", INVARIANT_ENV_FILE="/x/.env")
    assert "--env-file /x/.env" in args
    assert args.endswith("cis-ubuntu-linux-24-04 cis-debian-linux-12 cis-debian-linux-13")


def test_docker_failure_is_logged_and_exit_is_zero():
    with tempfile.TemporaryDirectory() as t:
        proc, _, _ = _run(Path(t), "exit 1")
    assert proc.returncode == 0
    assert "AVISO" in proc.stdout
