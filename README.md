# invariant_api

Control plane. The only `invariant_*` service that touches Postgres.
Orchestrates `invariant_assessment`/`invariant_ingestion` over HTTP and
serves the frontend's data.

Extracted from the `Invariant-Security/Invariant` monolith
(`src/invariant/{api,storage,cli}/`, `sql/`) as part of its split into
`invariant_*` services -- absorbs the persistence + orchestration that
used to live in `cli/extract.py`/`cli/import_document.py`/
`assessment.assess_target()`.

## Endpoints

- `GET /healthz`
- `GET /api/demo/status`, `GET /api/demo/runs`, `GET /api/demo/runs/latest`
  -- unchanged from the monolith's `api/main.py`.
- `POST /assess/{target}` -- calls `invariant_assessment`, joins the result
  against Postgres, returns `list[Finding]`.
- `POST /ingest/fetch/{document}`, `POST /ingest/extract/{document}`,
  `POST /ingest/normalize/{document}` -- calls `invariant_ingestion`,
  persists the result.

## Development

```bash
pip install -e ".[dev]"
alembic upgrade head          # needs DATABASE_URL in .env
uvicorn invariant_api.main:app --reload
```

`docker-compose.yml` brings up all 5 `invariant_*` services locally
(assumes the other 4 repos are cloned as sibling directories -- see its
own header comment).
