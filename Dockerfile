# syntax=docker/dockerfile:1
# python:3.12-slim (3.12.15) fixado por digest do índice -- atualizar
# conscientemente (README, "Locked dependencies").
ARG BASE=python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d
FROM ${BASE}

WORKDIR /app

# invariant_contracts is installed via a git+https direct reference below --
# the slim base has no git.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Dependências antes do código: mudar README/src não reinstala nada.
COPY requirements.lock requirements-vcs.txt ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock \
    && pip install --no-cache-dir --no-deps -r requirements-vcs.txt

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY sql/ ./sql/
COPY alembic.ini ./
RUN pip install --no-cache-dir --no-deps . && pip check

ENV INVARIANT_API_SQL_DIR=/app/sql
ENV INVARIANT_API_DATA_DEMO_DIR=/app/data/demo

EXPOSE 8000
CMD ["uvicorn", "invariant_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
