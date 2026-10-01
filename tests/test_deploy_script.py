"""scripts/deploy-api.sh contra uma stack compose descartável de verdade:
postgres + um "api" mínimo que responde a própria versão e tem a própria
"migration" (sucesso ou falha, gravado na imagem).

Prova a ordem exigida: migration roda com a imagem NOVA antes da troca; se
falhar, o container antigo (o mesmo, não um recriado) continua atendendo a
versão antiga.
"""

import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy-api.sh"

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker indisponível")

COMPOSE = """
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: deploy-teste
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 1s
      timeout: 3s
      retries: 30
  api:
    build: ./api
    depends_on: [postgres]
    healthcheck:
      test: ["CMD", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8000/version"]
      interval: 1s
      timeout: 3s
      retries: 30
"""

DOCKERFILE = """
FROM python:3.12-alpine
WORKDIR /app
COPY version migrate_rc migrate ./
CMD ["python", "-c", "import http.server as h; v=open('/app/version').read().encode(); \\
type('H',(h.BaseHTTPRequestHandler,),{'do_GET':lambda s:(s.send_response(200),s.end_headers(),s.wfile.write(v)),\\
'log_message':lambda *a:None}); h.ThreadingHTTPServer(('0.0.0.0',8000),\\
type('H',(h.BaseHTTPRequestHandler,),{'do_GET':lambda s:(s.send_response(200),s.end_headers(),s.wfile.write(v)),\\
'log_message':lambda *a:None})).serve_forever()"]
"""

MIGRATE = "sh /app/migrate"


@pytest.fixture
def stack(tmp_path):
    project = f"deploytest{uuid.uuid4().hex[:8]}"
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "Dockerfile").write_text(DOCKERFILE)
    (tmp_path / "api" / "migrate").write_text('exit "$(cat /app/migrate_rc)"\n')
    (tmp_path / "docker-compose.yml").write_text(COMPOSE)
    env = {"COMPOSE_PROJECT_NAME": project, "DEPLOY_MIGRATE_CMD": MIGRATE, "DEPLOY_WAIT_TIMEOUT": "60",
           "PATH": "/usr/local/bin:/usr/bin:/bin"}

    def dc(*args, check=True):
        return subprocess.run(["docker", "compose", "-f", "docker-compose.yml", *args], cwd=tmp_path, env=env,
                              capture_output=True, text=True, timeout=300, check=check)

    def release(version: str, migrate_rc: int):
        (tmp_path / "api" / "version").write_text(version)
        (tmp_path / "api" / "migrate_rc").write_text(str(migrate_rc))
        return subprocess.run(["sh", str(SCRIPT), "docker-compose.yml"], cwd=tmp_path, env=env,
                              capture_output=True, text=True, timeout=600)

    def serving() -> tuple[str, str]:
        cid = dc("ps", "-q", "api").stdout.strip()
        body = dc("exec", "-T", "api", "wget", "-q", "-O", "-", "http://127.0.0.1:8000/version").stdout
        return cid, body

    def image(ref: str) -> str:
        return subprocess.run(["docker", "image", "inspect", "-f", "{{.Id}}", ref],
                              capture_output=True, text=True).stdout.strip()

    try:
        yield release, serving, image, project
    finally:
        dc("down", "-v", "--rmi", "local", check=False)
        subprocess.run(["docker", "rmi", "-f", f"{project}-api:previous"], capture_output=True)


def test_failed_migration_keeps_the_old_container_serving(stack):
    release, serving, image, project = stack

    first = release("v1", 0)
    assert first.returncode == 0, first.stdout + first.stderr
    cid_v1, body = serving()
    assert body == "v1"
    v1_image = image(f"{project}-api")

    broken = release("v2", 1)
    out = broken.stdout + broken.stderr
    assert broken.returncode != 0, out
    assert "migration FALHOU" in out
    assert "4/4" not in out
    assert serving() == (cid_v1, "v1")  # o MESMO container, ainda na versão antiga

    fixed = release("v3", 0)
    assert fixed.returncode == 0, fixed.stdout + fixed.stderr
    cid_v3, body = serving()
    assert body == "v3" and cid_v3 != cid_v1
    # a imagem que estava no ar antes da troca bem-sucedida (v1; a v2 nunca entrou)
    assert image(f"{project}-api:previous") == v1_image
