# invariant_api

Control plane. The only `invariant_*` service that touches Postgres.
Orchestrates `invariant_assessment`, `invariant_ingestion` and
`invariant_discovery` over HTTP and serves the frontend's data. Owns the
compose stacks that run all of them.

Extracted from the `Invariant-Security/Invariant` monolith (now read-only
history). Pins `invariant_contracts@v0.2.0` (`pyproject.toml`).

## Compose stacks

Each stack has 6 services: `postgres`, `assessment`, `ingestion`,
`discovery`, `api` and `web`.

| File | Stack | Notes |
|---|---|---|
| `docker-compose.yml` | `invariant-next` (prod) | builds siblings from `../invariant_{assessment,ingestion,discovery,frontend}` |
| `docker-compose.dev.yml` | dev (teste.*) | same layout; Postgres published on `127.0.0.1:55432` |
| `docker-compose.appliance.yml` | appliance | with `nginx.appliance.conf` and `provision.sh` (TLS certificate) |

On the appliance, `bootstrap-documents.sh` runs once the stack is healthy
and loads the common CIS benchmarks through the ingest routes.

## Authentication

- **Admin session:** `routes/auth.py` (`/auth/status`, `/auth/setup`,
  `/auth/login`, `/auth/logout`, `/auth/me`) issues the `invariant_session`
  cookie, signed with `INVARIANT_API_SECRET_KEY`. Routes that need it depend
  on `auth.require_admin_session`.
- **Service-to-service:** `clients/internal_auth.py` sends
  `Authorization: Bearer <token>` with one token per service:
  `INVARIANT_INTERNAL_{ASSESSMENT,DISCOVERY,INGESTION}_TOKEN`. There is no
  shared token.
- **Fail-closed:** `main.require_secrets()` runs at startup. The API refuses
  to start if the session key or any of the 3 service tokens is unset.

## Routes

Admin-only routes are marked (admin).

- `GET /healthz`
- `/auth/*`: see above
- `POST /endpoints`, `POST /endpoints/bulk`, `GET /endpoints`,
  `DELETE /endpoints/{id}` (admin)
- `POST /endpoints/{id}/discover`, `GET /endpoints/{id}/results` (admin)
- `POST /endpoints/{id}/check`, `POST /endpoints/{id}/assess` (admin; SSH
  credentials are used for that one request and never stored)
- **v1:** `POST /endpoints/{id}/assessments` (accepts `Idempotency-Key`),
  `GET /endpoints/{id}/assessments`,
  `GET /endpoints/{id}/assessments/{assessment_id}` (admin; contract
  `AssessmentEnvelope`, persisted by `assessment_runs.py`)
- `POST /assess/{target}`, `GET /containers`, `GET /containers/{name}/check`
  (admin)
- `POST /ingest/fetch/{document}`, `POST /ingest/extract/{document}`,
  `POST /ingest/normalize/{document}` (**no admin check yet**)
- `POST /reports/pdf`, `GET /appliance/tls` (admin)
- `POST /demo-snapshot/{preview,publish,revoke}` (admin),
  `GET /demo-snapshot`, `GET /demo-snapshot/report`. The same set exists
  under `/demo-host-snapshot`.
- `GET /api/demo/status`, `GET /api/demo/runs`, `GET /api/demo/runs/latest`
- `POST /leads`, `POST /newsletter/subscribe` (public)

## Database

All SQL is hand-written:

- `sql/schema/000NN_*.sql`: the DDL. Each Alembic migration in
  `sql/migrations/versions/` `op.execute()`s one schema file and has a
  hand-written downgrade.
- `sql/queries/*.sql`: loaded by `storage/postgres.py` from
  `INVARIANT_API_SQL_DIR` (set to `/app/sql` in the image).
- A new table needs a schema file, a migration and its queries.

`alembic.ini` points at `sql/migrations`. `env.py` reads `DATABASE_URL`
from the environment.

## Deploy

`scripts/deploy-api.sh <compose-file>` is called by `deploy.yml` (main,
`docker-compose.yml`) and `deploy-dev.yml` (dev, `docker-compose.dev.yml`).
It runs these steps in order:

1. Starts `postgres` and waits for it.
2. Tags the running api image `:previous`.
3. Builds the new image. The old container keeps serving.
4. Runs `alembic upgrade head` in the new image. If it fails, the script
   stops and nothing is swapped.
5. Swaps the container (`up --no-build --wait`) and waits for the
   healthcheck.

Migrations must stay additive: the old code runs against the new schema
between steps 4 and 5. Rollback:
`docker tag <image>:previous <image>:latest && docker compose up -d --no-build api`.

## Development

```bash
pip install -e ".[dev]"
alembic upgrade head          # needs DATABASE_URL
uvicorn invariant_api.main:app --reload
```

Tests run `DELETE FROM` on real tables. Point `DATABASE_URL` at
`invariant_test` on `localhost:55432`, never at `invariant`.
`tests/api/conftest.py` refuses any database without `test` in its name.
The only exception is a GitHub-hosted runner
(`RUNNER_ENVIRONMENT=github-hosted`). Runs that use the shared dev Postgres
or the fixture containers are scheduled one at a time.

## Locked dependencies

`requirements.lock` (hashed) + `requirements-vcs.txt` (contracts, exact commit) are what the image and CI install; `pyproject.toml` keeps the loose ranges.
Regenerate (add/bump a dep): in `python:3.12-slim@<digest>`, `pip install pip-tools && pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements.lock` with the deps from `pyproject.toml` (minus `invariant_contracts`) as input; bump contracts by editing the commit in `requirements-vcs.txt`.
Bump the base: `docker buildx imagetools inspect python:3.12-slim` → put the index `Digest:` in the Dockerfile `ARG BASE`, then rebuild and run `pip check`.
