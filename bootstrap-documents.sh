#!/usr/bin/env bash
# Roda depois do stack subir saudável (ExecStartPost do invariant.service,
# ou no final do install.sh) -- garante que o appliance já nasce com os
# benchmarks CIS mais comuns carregados, em vez de precisar de um operador
# rodando fetch/extract/normalize manualmente antes do primeiro assessment
# funcionar. Gap achado no primeiro ensaio ponta-a-ponta real (12/09/2026,
# LXD): banco de um install novo é completamente vazio -- todo assessment
# falha com 422 até alguém ingerir o documento do SO do alvo.
#
# Roda a ingestão DENTRO do container api (python -m
# invariant_api.bootstrap_documents), não pelas rotas /api/ingest/*: elas
# exigem sessão de admin e num appliance novo ainda não existe admin.
#
# Idempotente e barato em reboots subsequentes: pra cada documento, tenta
# normalize primeiro (sucede se o document_version já existe) antes de
# rodar fetch+extract, que são caros (~30s, crawl+parse de PDF real contra
# cisecurity.org).
#
# Nunca deve derrubar a unit inteira -- por isso o "-" antes do path no
# ExecStartPost do invariant.service: um benchmark que não baixou (rede
# instável, site fora do ar) não pode impedir o resto do appliance de
# subir. Erros de um documento são só logados, os outros continuam.
set -uo pipefail

# O compose é resolvido pelo diretório do próprio script (install.sh chama de
# um cwd arbitrário; o systemd, de /opt/invariant).
DIR="$(dirname "$(readlink -f "$0")")"
# Default é exatamente o que os alvos reais desta VPS precisam hoje (host
# Ubuntu 24.04 + containers de produção em Debian 12/13) -- sobrescrevível
# via INVARIANT_BOOTSTRAP_DOCUMENTS (separado por espaço) em
# /etc/invariant/.env se um cliente/demo precisar de outro documento (ver
# KNOWN_CIS_DOCUMENTS em invariant_ingestion pra chaves válidas).
DOCUMENTS="${INVARIANT_BOOTSTRAP_DOCUMENTS:-cis-ubuntu-linux-24-04 cis-debian-linux-12 cis-debian-linux-13}"

# shellcheck disable=SC2086  # DOCUMENTS é uma lista separada por espaço
docker compose -f "$DIR/docker-compose.appliance.yml" \
    --env-file "${INVARIANT_ENV_FILE:-/etc/invariant/.env}" \
    exec -T api python -m invariant_api.bootstrap_documents $DOCUMENTS \
    || echo "[bootstrap-documents] AVISO: não foi possível rodar a ingestão no container api."
exit 0
