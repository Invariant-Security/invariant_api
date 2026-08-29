# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# invariant_contracts is installed via a git+https direct reference below --
# the slim base has no git.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY sql/ ./sql/
COPY alembic.ini ./
RUN pip install --no-cache-dir .

ENV INVARIANT_API_SQL_DIR=/app/sql

EXPOSE 8000
CMD ["uvicorn", "invariant_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
