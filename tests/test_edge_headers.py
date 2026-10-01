"""Headers internos morrem na borda do appliance.

Estático: toda rota do nginx.appliance.conf que repassa para dentro zera
cada header de RESERVED_INTERNAL_HEADERS.
Real: um nginx de verdade com esse arquivo, na frente de um servidor que
devolve os headers recebidos, não deixa passar nenhum deles.
"""

import json
import re
import shutil
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

from invariant_api.edge_headers import RESERVED_INTERNAL_HEADERS

CONF = Path(__file__).resolve().parents[1] / "nginx.appliance.conf"


def _proxied_locations(text: str) -> dict[str, str]:
    blocks = {}
    for match in re.finditer(r"location\s+([^\s{]+)\s*\{(.*?)\n  \}", text, re.S):
        path, body = match.group(1), match.group(2)
        if "proxy_pass" in body:
            blocks[path] = body
    return blocks


def test_every_proxied_location_strips_every_reserved_header():
    blocks = _proxied_locations(CONF.read_text())
    assert set(blocks) >= {"/api/", "/auth/"}
    for path, body in blocks.items():
        for header in RESERVED_INTERNAL_HEADERS:
            assert re.search(rf'proxy_set_header\s+{re.escape(header)}\s+"";', body), f"{path} não zera {header}"
        assert re.search(r'proxy_set_header\s+Authorization\s+"";', body), f"{path} não zera Authorization"


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


def _docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=180, check=check)


@pytest.fixture(scope="module")
def edge_url():
    if shutil.which("docker") is None:
        pytest.skip("docker indisponível")
    tag = uuid.uuid4().hex[:8]
    net, echo, edge = f"edge-net-{tag}", f"edge-echo-{tag}", f"edge-nginx-{tag}"
    _docker("network", "create", net)
    try:
        _docker("run", "-d", "--name", echo, "--network", net, "--network-alias", "api",
                "python:3.12-alpine", "python", "-c", ECHO_SERVER)
        _docker("run", "-d", "--name", edge, "--network", net, "-p", "127.0.0.1::80",
                "-v", f"{CONF}:/etc/nginx/conf.d/default.conf:ro", "nginx:stable-alpine")
        port = _docker("port", edge, "80/tcp").stdout.strip().split(":")[-1]
        url = f"http://127.0.0.1:{port}"
        deadline = time.time() + 30
        while True:
            try:
                urllib.request.urlopen(url + "/api/ping", timeout=2)
                break
            except Exception:
                assert time.time() < deadline, _docker("logs", edge, check=False).stderr
                time.sleep(0.3)
        yield url
    finally:
        _docker("rm", "-f", echo, edge, check=False)
        _docker("network", "rm", net, check=False)


@pytest.mark.parametrize("path", ["/api/endpoints", "/auth/me"])
def test_reserved_headers_do_not_reach_the_api(edge_url, path):
    req = urllib.request.Request(edge_url + path)
    for header in RESERVED_INTERNAL_HEADERS:
        req.add_header(header, "forjado-pelo-cliente")
    req.add_header("Authorization", "Bearer forjado-pelo-cliente")
    req.add_header("Cookie", "invariant_session=valor-legitimo")
    with urllib.request.urlopen(req, timeout=10) as resp:
        seen = json.loads(resp.read())
    for header in (*RESERVED_INTERNAL_HEADERS, "Authorization"):
        assert header.lower() not in seen, f"{header} atravessou a borda em {path}"
    assert "forjado-pelo-cliente" not in json.dumps(seen)
    assert seen.get("cookie") == "invariant_session=valor-legitimo"
