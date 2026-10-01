"""Informações da própria instalação para o console (só admin).

GET /appliance/tls: impressão digital do certificado HTTPS que a borda do
appliance apresenta, para o cliente ou o vendedor conferir/fixar. Lê só o
certificado PÚBLICO (INVARIANT_TLS_CERT_FILE, montado read-only pelo
compose) -- a chave privada nunca chega a este container. Nas instalações
hospedadas (TLS no Cloudflare/nginx-proxy) o arquivo não existe e a rota
responde available=false.
"""

import os
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import APIRouter, Depends

from invariant_api.auth import require_admin_session

router = APIRouter(prefix="/appliance", dependencies=[Depends(require_admin_session)])

CERT_FILE_ENV = "INVARIANT_TLS_CERT_FILE"
_FIRST_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def _colon_hex(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


@router.get("/tls")
def tls_info() -> dict:
    path = os.environ.get(CERT_FILE_ENV, "")
    if not path or not os.path.isfile(path):
        return {"available": False}
    with open(path, "rb") as f:
        match = _FIRST_PEM.search(f.read())  # cadeia da empresa: o 1º é o do servidor
    if match is None:
        return {"available": False}
    cert = x509.load_pem_x509_certificate(match.group(0))
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_addresses = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_addresses = [], []
    return {
        "available": True,
        "sha256": _colon_hex(cert.fingerprint(hashes.SHA256())),
        "subject": cert.subject.rfc4514_string(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "dns_names": dns_names,
        "ip_addresses": ip_addresses,
    }
