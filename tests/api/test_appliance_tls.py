"""GET /appliance/tls com o certificado real gerado pelo provision.sh,
conferido contra o openssl de linha de comando."""

import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from invariant_api import main
from invariant_api.auth import create_session_cookie
from invariant_api.routes.appliance import CERT_FILE_ENV

PROVISION = Path(__file__).resolve().parents[2] / "provision.sh"


@pytest.fixture(scope="module")
def tls_dir(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("appliance")
    proc = subprocess.run(["sh", str(PROVISION), str(tmp / ".env"), str(tmp / "tls")],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return tmp / "tls"


@pytest.fixture
def admin():
    client = TestClient(main.app)
    client.cookies.set("invariant_session", create_session_cookie("admin"))
    return client


def _openssl_fingerprint(cert: Path) -> str:
    out = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"],
                         check=True, capture_output=True, text=True).stdout
    return out.strip().split("=", 1)[1]


def test_fingerprint_matches_openssl(admin, tls_dir, monkeypatch):
    monkeypatch.setenv(CERT_FILE_ENV, str(tls_dir / "cert.pem"))
    body = admin.get("/appliance/tls").json()
    assert body["available"] is True
    assert body["sha256"] == _openssl_fingerprint(tls_dir / "cert.pem")
    assert "127.0.0.1" in body["ip_addresses"] and "localhost" in body["dns_names"]
    assert body["not_after"] > "2028"


def test_requires_admin_session(tls_dir, monkeypatch):
    monkeypatch.setenv(CERT_FILE_ENV, str(tls_dir / "cert.pem"))
    assert TestClient(main.app).get("/appliance/tls").status_code == 401


@pytest.mark.parametrize("path", ["", "/nao/existe/cert.pem"])
def test_hosted_install_without_cert_reports_unavailable(admin, monkeypatch, path):
    monkeypatch.setenv(CERT_FILE_ENV, path)
    assert admin.get("/appliance/tls").json() == {"available": False}


def test_company_chain_uses_the_server_certificate(admin, tls_dir, tmp_path, monkeypatch):
    ca_key, ca_cert = tmp_path / "ca-key.pem", tmp_path / "ca-cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                    "-subj", "/CN=ca.example", "-keyout", str(ca_key), "-out", str(ca_cert)],
                   check=True, capture_output=True)
    chain = tmp_path / "chain.pem"
    chain.write_text((tls_dir / "cert.pem").read_text() + ca_cert.read_text())
    monkeypatch.setenv(CERT_FILE_ENV, str(chain))
    assert admin.get("/appliance/tls").json()["sha256"] == _openssl_fingerprint(tls_dir / "cert.pem")


def test_private_key_never_appears(admin, tls_dir, monkeypatch):
    monkeypatch.setenv(CERT_FILE_ENV, str(tls_dir / "cert.pem"))
    assert "PRIVATE" not in admin.get("/appliance/tls").text
