"""Sobe a borda do appliance de verdade para testes: o nginx.appliance.conf
como template (mesmo mecanismo do compose), com o certificado gerado pelo
provision.sh real, na frente de um servidor que devolve os headers que
recebeu no lugar do container `api`."""

import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "nginx.appliance.conf"
PROVISION = ROOT / "provision.sh"

ECHO_SERVER = """
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def _r(self):
        body = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = _r
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
"""

INSECURE = ssl.create_default_context()
INSECURE.check_hostname = False
INSECURE.verify_mode = ssl.CERT_NONE


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=180, check=check)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


NO_REDIRECT = urllib.request.build_opener(_NoRedirect)


@contextmanager
def appliance_edge(https_port_label: str = "443"):
    """Rende (http_url, https_url, tls_dir). `https_port_label` é o valor de
    INVARIANT_HTTPS_PORT usado no redirecionamento."""
    tag = uuid.uuid4().hex[:8]
    net, echo, edge = f"edge-net-{tag}", f"edge-echo-{tag}", f"edge-nginx-{tag}"
    with tempfile.TemporaryDirectory() as tmp:
        tls = Path(tmp) / "tls"
        subprocess.run(["sh", str(PROVISION), str(Path(tmp) / ".env"), str(tls)],
                       check=True, capture_output=True, text=True, timeout=60)
        # a chave fica 600 do usuário dos testes; o nginx do container roda
        # o master como root e lê normalmente
        _docker("network", "create", net)
        try:
            _docker("run", "-d", "--name", echo, "--network", net, "--network-alias", "api",
                    "python:3.12-alpine", "python", "-c", ECHO_SERVER)
            _docker("run", "-d", "--name", edge, "--network", net,
                    "-p", "127.0.0.1::80", "-p", "127.0.0.1::443",
                    "-e", f"INVARIANT_HTTPS_PORT={https_port_label}", "-e", "NGINX_ENVSUBST_FILTER=^INVARIANT_",
                    "-v", f"{TEMPLATE}:/etc/nginx/templates/default.conf.template:ro",
                    "-v", f"{tls}:/etc/nginx/tls:ro",
                    "nginx:stable-alpine")
            http_port = _docker("port", edge, "80/tcp").stdout.strip().splitlines()[0].split(":")[-1]
            https_port = _docker("port", edge, "443/tcp").stdout.strip().splitlines()[0].split(":")[-1]
            http_url, https_url = f"http://127.0.0.1:{http_port}", f"https://127.0.0.1:{https_port}"
            deadline = time.time() + 30
            while True:
                try:
                    urllib.request.urlopen(https_url + "/api/ping", timeout=2, context=INSECURE)
                    break
                except Exception:
                    assert time.time() < deadline, _docker("logs", edge, check=False).stderr[-2000:]
                    time.sleep(0.3)
            yield http_url, https_url, tls
        finally:
            _docker("rm", "-f", echo, edge, check=False)
            _docker("network", "rm", net, check=False)
