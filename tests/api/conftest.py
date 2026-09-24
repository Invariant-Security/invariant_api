"""Shared safety net for tests/api/*'s clean_tables-style fixtures.

2026-09-24 incident: every test file here has its own autouse fixture that
runs DELETE FROM against db.connect()'s DATABASE_URL before AND after each
test (duplicated on purpose, not centralized -- each file's set of tables
differs). db.connect() silently loads .env if DATABASE_URL isn't already in
the environment, and .env's DATABASE_URL pointed at the SAME persistent
Postgres that backs the real, running teste.invariantsec.org -- not a
disposable test database. Every local pytest run against tests/api/ was
quietly wiping real dev data (endpoints, leads, admin_users...). Root cause
fixed by giving local test runs their own `invariant_test` database (see
.env.example), but this assertion is the actual backstop: it refuses to run
if DATABASE_URL ever again resolves to anything that isn't unmistakably a
test database, regardless of why.
"""


def assert_test_database(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        (name,) = cur.fetchone()
    if "test" not in name:
        conn.close()
        raise RuntimeError(
            f"refusing to run destructive test fixtures against database {name!r} -- "
            "it doesn't look like a disposable test database (no 'test' in its name). "
            "This exact mistake wiped real dev data on 2026-09-24: check DATABASE_URL "
            "(likely coming from .env) and point it at invariant_test instead. See "
            "tests/api/conftest.py and .env.example."
        )
