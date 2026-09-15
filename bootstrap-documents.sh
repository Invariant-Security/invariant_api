#!/usr/bin/env bash
# Roda depois do stack subir saudável (ExecStartPost do invariant.service,
# ou no final do install.sh) -- garante que o appliance já nasce com os
# benchmarks CIS mais comuns carregados, em vez de precisar de um operador
# rodando fetch/extract/normalize manualmente antes do primeiro assessment
# funcionar. Gap achado no primeiro ensaio ponta-a-ponta real (12/09/2026,
# LXD): banco de um install novo é completamente vazio -- todo assessment
# falha com 422 até alguém ingerir o documento do SO do alvo.
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

WEB_PORT="${INVARIANT_WEB_PORT:-80}"
BASE="http://127.0.0.1:${WEB_PORT}/api"
# Default é exatamente o que os alvos reais desta VPS precisam hoje (host
# Ubuntu 24.04 + containers de produção em Debian 12/13) -- sobrescrevível
# via INVARIANT_BOOTSTRAP_DOCUMENTS (separado por espaço) em
# /etc/invariant/.env se um cliente/demo precisar de outro documento (ver
# KNOWN_CIS_DOCUMENTS em invariant_ingestion pra chaves válidas).
DOCUMENTS="${INVARIANT_BOOTSTRAP_DOCUMENTS:-cis-ubuntu-linux-24-04 cis-debian-linux-12 cis-debian-linux-13}"

log() { echo "[bootstrap-documents] $1"; }

for doc in $DOCUMENTS; do
    # KNOWN_CIS_DOCUMENTS's document_slug é sempre a chave sem "cis-" e com
    # "-" trocado por "_" (ex. cis-ubuntu-linux-24-04 -> ubuntu_linux_24_04)
    # -- é essa forma que /ingest/normalize/{document} espera, diferente de
    # fetch/extract, que usam a chave com hífen. Mesma inconsistência de
    # slug em toda a API, não introduzida aqui.
    underscored="${doc#cis-}"
    underscored="${underscored//-/_}"

    status="$(curl -fsS -o /dev/null -w '%{http_code}' -X POST "${BASE}/ingest/normalize/${underscored}" 2>/dev/null || echo 000)"
    if [ "$status" = "200" ]; then
        log "$doc já ingerido, pulando."
        continue
    fi

    log "Ingerindo $doc (fetch + extract + normalize, primeira vez -- pode levar ~30s)..."
    if ! curl -fsS -X POST "${BASE}/ingest/fetch/${doc}" >/dev/null; then
        log "AVISO: fetch de $doc falhou, pulando (rode manualmente depois se precisar)."
        continue
    fi
    if ! curl -fsS -X POST "${BASE}/ingest/extract/${doc}" >/dev/null; then
        log "AVISO: extract de $doc falhou, pulando."
        continue
    fi
    if ! curl -fsS -X POST "${BASE}/ingest/normalize/${underscored}" >/dev/null; then
        log "AVISO: normalize de $doc falhou, pulando."
        continue
    fi
    log "$doc ingerido com sucesso."
done

log "Bootstrap de documentos concluído."
