"""HTTPS do appliance com nginx real, template do compose e certificado do
provision.sh."""

import hashlib
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlparse

import pytest
from appliance_edge import INSECURE, NO_REDIRECT, appliance_edge, docker_available

pytestmark = pytest.mark.skipif(not docker_available(), reason="docker indisponível")


@pytest.fixture(scope="module")
def edge():
    with appliance_edge() as urls:
        yield urls


def _status_and_location(url):
    try:
        resp = NO_REDIRECT.open(url, timeout=10)
        return resp.status, resp.headers.get("Location"), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location"), e.read()


def test_port_80_answers_only_healthz(edge):
    http_url, _, _ = edge
    status, _, body = _status_and_location(http_url + "/healthz")
    assert (status, body) == (200, b"ok\n")


@pytest.mark.parametrize("path", ["/", "/endpoints?x=1", "/api/endpoints", "/auth/me"])
def test_everything_else_on_80_redirects_to_https(edge, path):
    http_url, _, _ = edge
    status, location, _ = _status_and_location(http_url + path)
    assert status == 301
    assert location == f"https://127.0.0.1:443{path}"


def test_redirect_uses_the_configured_https_port():
    with appliance_edge(https_port_label="8443") as (http_url, _, _):
        status, location, _ = _status_and_location(http_url + "/endpoints")
    assert (status, location) == (301, "https://127.0.0.1:8443/endpoints")


def test_https_serves_the_console_with_hsts(edge):
    _, https_url, _ = edge
    with urllib.request.urlopen(https_url + "/", timeout=10, context=INSECURE) as resp:
        assert resp.status == 200
        assert resp.headers.get("Strict-Transport-Security") == "max-age=31536000"


def _served_cert_der(https_url):
    parsed = urlparse(https_url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=10) as sock:
        with INSECURE.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
            return tls.getpeercert(binary_form=True), tls.version()


def test_served_certificate_is_the_one_on_disk(edge):
    _, https_url, tls_dir = edge
    served, version = _served_cert_der(https_url)
    on_disk = ssl.PEM_cert_to_DER_cert((tls_dir / "cert.pem").read_text())
    assert hashlib.sha256(served).hexdigest() == hashlib.sha256(on_disk).hexdigest()
    assert version in ("TLSv1.2", "TLSv1.3")
