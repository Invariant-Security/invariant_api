"""provision.sh rodando de verdade num Debian 12 limpo (container real).

Garante: segredos separados gerados uma vez; reinstalação não muda nada;
.env antigo só ganha o que falta; rotacionar sessão/tokens não altera a
chave de cobrança nem o ID da instalação; certificado gerado uma vez com
permissões restritas e SAN real; certificado da empresa nunca sobrescrito.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "provision.sh"

SECRETS = (
    "INVARIANT_API_SECRET_KEY",
    "INVARIANT_INTERNAL_ASSESSMENT_TOKEN",
    "INVARIANT_INTERNAL_DISCOVERY_TOKEN",
    "INVARIANT_INTERNAL_INGESTION_TOKEN",
    "INVARIANT_INTERNAL_GATEWAY_TOKEN",
    "INVARIANT_USAGE_HMAC_KEY",
)

# Roda todos os cenários dentro de um único container e imprime um JSON
# por etapa; o Python só compara. `snap` captura .env, permissões e o
# fingerprint/SAN do certificado.
SCENARIO = r"""
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq openssl hostname >/dev/null
E=/etc/invariant/.env; T=/etc/invariant/tls; P="sh /provision.sh $E $T"
snap() {
  env_json=$(awk -F= 'NF{k=$1; sub(/^[^=]*=/,""); printf "%s\"%s\":\"%s\"", (n++?",":""), k, $0}' "$E")
  fp=$(openssl x509 -in $T/cert.pem -noout -fingerprint -sha256 | cut -d= -f2)
  san=$(openssl x509 -in $T/cert.pem -noout -ext subjectAltName | tail -1 | tr -d ' ')
  days=$(( ( $(date -d "$(openssl x509 -in $T/cert.pem -noout -enddate | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
  echo "{\"step\":\"$1\",\"env\":{${env_json}},\"env_mode\":\"$(stat -c %a $E)\",\"key_mode\":\"$(stat -c %a $T/key.pem)\",\"cert_mode\":\"$(stat -c %a $T/cert.pem)\",\"fp\":\"$fp\",\"san\":\"$san\",\"days\":$days,\"host\":\"$(hostname -f 2>/dev/null || hostname)\",\"usage_lines\":$(grep -c '^INVARIANT_USAGE_HMAC_KEY=' $E)}"
}
$P >/dev/null; snap fresh
$P >/dev/null; snap reinstall
# rotação: remove sessão e tokens; cobrança e ID têm que sobreviver
sed -i '/^INVARIANT_API_SECRET_KEY=/d;/^INVARIANT_INTERNAL_/d' $E
$P >/dev/null; snap rotated
# certificado da empresa: substitui os dois arquivos; provision não toca
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=empresa.example -keyout $T/key.pem -out $T/cert.pem 2>/dev/null
$P >/dev/null; snap custom_cert
# .env antigo de uma versão anterior: só sessão + porta, e uma linha vazia
rm -rf /etc/invariant; mkdir -p /etc/invariant
printf 'INVARIANT_API_SECRET_KEY=valor-antigo\nINVARIANT_WEB_PORT=8080\nINVARIANT_USAGE_HMAC_KEY=\n' > $E
$P >/dev/null; snap upgraded_old_env
"""


@pytest.fixture(scope="module")
def steps():
    if shutil.which("docker") is None:
        pytest.skip("docker indisponível")
    proc = subprocess.run(
        ["docker", "run", "--rm", "--hostname", "appliance-teste", "-v", f"{SCRIPT}:/provision.sh:ro",
         "debian:12", "bash", "-c", SCENARIO],
        capture_output=True, text=True, timeout=600,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    return {s["step"]: s for s in (json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{"))}


def test_fresh_install_generates_every_separate_secret(steps):
    env = steps["fresh"]["env"]
    for name in SECRETS:
        assert re.fullmatch(r"[0-9a-f]{64}", env[name]), name
    assert re.fullmatch(r"[0-9a-f-]{36}", env["INVARIANT_INSTALLATION_ID"])
    assert len({env[name] for name in SECRETS}) == len(SECRETS), "segredos repetidos entre funções"


def test_files_have_restricted_permissions(steps):
    s = steps["fresh"]
    assert (s["env_mode"], s["key_mode"], s["cert_mode"]) == ("600", "600", "644")


def test_certificate_has_real_san_and_long_validity(steps):
    s = steps["fresh"]
    assert f"DNS:{s['host']}" in s["san"] and "IPAddress:127.0.0.1" in s["san"]
    # além do loopback, o IP real da máquina (o que o cliente vai digitar)
    assert re.search(r"IPAddress:(?!127\.0\.0\.1)[0-9a-f.:]+", s["san"]), s["san"]
    assert 1000 < s["days"] <= 1095


def test_reinstall_changes_nothing(steps):
    assert steps["reinstall"]["env"] == steps["fresh"]["env"]
    assert steps["reinstall"]["fp"] == steps["fresh"]["fp"]


def test_rotating_session_and_tokens_keeps_billing_identity(steps):
    before, after = steps["fresh"]["env"], steps["rotated"]["env"]
    assert after["INVARIANT_USAGE_HMAC_KEY"] == before["INVARIANT_USAGE_HMAC_KEY"]
    assert after["INVARIANT_INSTALLATION_ID"] == before["INVARIANT_INSTALLATION_ID"]
    assert after["INVARIANT_API_SECRET_KEY"] != before["INVARIANT_API_SECRET_KEY"]
    assert after["INVARIANT_INTERNAL_DISCOVERY_TOKEN"] != before["INVARIANT_INTERNAL_DISCOVERY_TOKEN"]


def test_customer_certificate_is_never_overwritten(steps):
    assert steps["custom_cert"]["fp"] != steps["rotated"]["fp"]
    assert "empresa.example" not in steps["custom_cert"]["san"]  # sem SAN: é o cert da empresa, intacto
    assert steps["custom_cert"]["days"] <= 30


def test_old_env_keeps_values_and_gains_only_what_is_missing(steps):
    env = steps["upgraded_old_env"]["env"]
    assert env["INVARIANT_API_SECRET_KEY"] == "valor-antigo"
    assert env["INVARIANT_WEB_PORT"] == "8080"
    assert re.fullmatch(r"[0-9a-f]{64}", env["INVARIANT_USAGE_HMAC_KEY"]), "linha vazia deve ser preenchida"
    assert steps["upgraded_old_env"]["usage_lines"] == 1, "a linha vazia antiga deve ser substituída, não duplicada"
