#!/bin/sh
# Provisiona segredos e certificado HTTPS de uma instalação do appliance.
# Chamado pelos dois canais de instalação (postinst do .deb e install.sh),
# a cada instalação E a cada atualização.
#
# Regra única: só ACRESCENTA o que falta, nunca troca o que já existe.
# - Segredos separados por função; nenhum derivado de outro:
#     INVARIANT_API_SECRET_KEY            sessão do console
#     INVARIANT_INTERNAL_*_TOKEN          um por serviço interno
#     INVARIANT_INTERNAL_GATEWAY_TOKEN    gateway -> api
#     INVARIANT_USAGE_HMAC_KEY            identidade de cobrança (NUNCA rotacionar)
#     INVARIANT_INSTALLATION_ID           identidade da instalação (NUNCA mudar)
#   Rotacionar sessão/tokens (apagar a linha e rodar de novo) não toca a
#   chave de cobrança nem o ID da instalação.
# - Certificado HTTPS autoassinado gerado uma única vez em $TLS_DIR
#   (key.pem 600, cert.pem 644). Para usar o certificado da empresa,
#   substitua os dois arquivos; este script nunca os sobrescreve.
#
# Uso: provision.sh [ENV_FILE] [TLS_DIR]
set -eu

ENV_FILE="${1:-/etc/invariant/.env}"
TLS_DIR="${2:-/etc/invariant/tls}"

umask 077
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

# Presente E não vazio. Uma linha vazia ("X=") conta como ausente.
has_value() {
    grep -q "^$1=." "$ENV_FILE"
}

add_if_missing() {
    if ! has_value "$1"; then
        sed -i "/^$1=/d" "$ENV_FILE"
        printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
        echo "provision: $1 gerado"
    fi
}

random_hex() {
    openssl rand -hex 32
}

for name in \
    INVARIANT_API_SECRET_KEY \
    INVARIANT_INTERNAL_ASSESSMENT_TOKEN \
    INVARIANT_INTERNAL_DISCOVERY_TOKEN \
    INVARIANT_INTERNAL_INGESTION_TOKEN \
    INVARIANT_INTERNAL_GATEWAY_TOKEN \
    INVARIANT_USAGE_HMAC_KEY
do
    has_value "$name" || add_if_missing "$name" "$(random_hex)"
done
has_value INVARIANT_INSTALLATION_ID || add_if_missing INVARIANT_INSTALLATION_ID "$(cat /proc/sys/kernel/random/uuid)"

# --- certificado HTTPS ------------------------------------------------------
if [ -s "$TLS_DIR/cert.pem" ] && [ -s "$TLS_DIR/key.pem" ]; then
    echo "provision: certificado existente em $TLS_DIR mantido"
else
    umask 022
    mkdir -p "$TLS_DIR"
    chmod 755 "$TLS_DIR"
    host="$(hostname -f 2>/dev/null || hostname)"
    san="DNS:${host},DNS:localhost,IP:127.0.0.1"
    for ip in $(hostname -I 2>/dev/null || true); do
        case "$ip" in
            *:*) san="${san},IP:${ip}" ;;   # IPv6
            *.*) san="${san},IP:${ip}" ;;   # IPv4
        esac
    done
    tmp="$(mktemp -d)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -days 1095 -subj "/CN=${host}" -addext "subjectAltName=${san}" \
        -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null
    install -m 600 "$tmp/key.pem" "$TLS_DIR/key.pem"
    install -m 644 "$tmp/cert.pem" "$TLS_DIR/cert.pem"
    rm -rf "$tmp"
    echo "provision: certificado autoassinado gerado em $TLS_DIR (SAN: ${san})"
fi
