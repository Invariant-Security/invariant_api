# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY sql/ ./sql/
COPY alembic.ini ./
RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "invariant_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
