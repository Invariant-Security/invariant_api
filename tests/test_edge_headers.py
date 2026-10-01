"""Headers internos morrem na borda do appliance.

Estático: toda rota do nginx.appliance.conf que repassa para dentro zera
cada header de RESERVED_INTERNAL_HEADERS.
Real: o nginx de verdade com esse arquivo (HTTPS, como no appliance), na
frente de um servidor que devolve os headers recebidos, não deixa passar
nenhum deles.
"""

import json
import re
import urllib.request
from pathlib import Path

import pytest
from appliance_edge import INSECURE, appliance_edge, docker_available

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


@pytest.fixture(scope="module")
def edge_url():
    if not docker_available():
        pytest.skip("docker indisponível")
    with appliance_edge() as (_http, https_url, _tls):
        yield https_url


@pytest.mark.parametrize("path", ["/api/endpoints", "/auth/me"])
def test_reserved_headers_do_not_reach_the_api(edge_url, path):
    req = urllib.request.Request(edge_url + path)
    for header in RESERVED_INTERNAL_HEADERS:
        req.add_header(header, "forjado-pelo-cliente")
    req.add_header("Authorization", "Bearer forjado-pelo-cliente")
    req.add_header("Cookie", "invariant_session=valor-legitimo")
    with urllib.request.urlopen(req, timeout=10, context=INSECURE) as resp:
        seen = json.loads(resp.read())
    for header in (*RESERVED_INTERNAL_HEADERS, "Authorization"):
        assert header.lower() not in seen, f"{header} atravessou a borda em {path}"
    assert "forjado-pelo-cliente" not in json.dumps(seen)
    assert seen.get("cookie") == "invariant_session=valor-legitimo"
