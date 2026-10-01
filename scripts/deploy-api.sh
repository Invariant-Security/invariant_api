#!/bin/sh
# Deploy do api numa stack compose, com as migrations ANTES da troca de
# container. Chamado pelos workflows deploy.yml (main) e deploy-dev.yml (dev),
# de dentro do STACK_DIR.
#
#   1. banco no ar (não mexe no api);
#   2. build da imagem nova -- o container antigo continua atendendo;
#   3. migrations rodando NA IMAGEM NOVA (compose run --rm);
#      falhou -> sai com erro aqui e o container antigo segue intacto;
#   4. só então troca o container (up --no-build) e espera o healthcheck;
#   A imagem que está no ar é marcada <imagem>:previous ANTES do build --
#   depois que a tag passa para a imagem nova e o container antigo sai, a
#   anterior fica sem referência e o Docker a descarta. Rollback:
#      docker tag <imagem>:previous <imagem>:latest && compose up -d --no-build api
#
# Migrations precisam ser compatíveis com o código anterior durante o passo
# 3->4 (aditivas). Uma migration destrutiva exige deploy em duas etapas.
#
# Uso: scripts/deploy-api.sh <arquivo-compose>
# Variáveis (para teste): DEPLOY_SERVICE=api DEPLOY_DB_SERVICE=postgres
#                          DEPLOY_MIGRATE_CMD="alembic upgrade head"
set -eu

COMPOSE_FILE="$1"
SERVICE="${DEPLOY_SERVICE:-api}"
DB_SERVICE="${DEPLOY_DB_SERVICE:-postgres}"
MIGRATE_CMD="${DEPLOY_MIGRATE_CMD:-alembic upgrade head}"
WAIT="${DEPLOY_WAIT_TIMEOUT:-180}"

dc() { docker compose -f "$COMPOSE_FILE" "$@"; }

running_image() {
    cid="$(dc ps -q "$SERVICE" 2>/dev/null || true)"
    [ -n "$cid" ] && docker inspect -f '{{.Image}}' "$cid" || true
}

echo "deploy: 1/4 banco"
dc up -d --wait --wait-timeout "$WAIT" "$DB_SERVICE"

old_image="$(running_image)"
if [ -n "$old_image" ]; then
    name="$(docker inspect -f '{{.Config.Image}}' "$(dc ps -q "$SERVICE")")"
    name="${name%:*}"
    docker tag "$old_image" "${name}:previous"
    echo "deploy: imagem no ar marcada ${name}:previous"
fi

echo "deploy: 2/4 build da imagem nova (o container atual continua no ar)"
dc build "$SERVICE"

echo "deploy: 3/4 migrations com a imagem nova"
# shellcheck disable=SC2086  # MIGRATE_CMD é um comando com argumentos
if ! dc run --rm --no-deps "$SERVICE" $MIGRATE_CMD; then
    echo "deploy: migration FALHOU -- container anterior mantido no ar, nada trocado" >&2
    exit 1
fi

echo "deploy: 4/4 troca do container + healthcheck"
dc up -d --no-build --wait --wait-timeout "$WAIT" "$SERVICE"
echo "deploy: ok"
