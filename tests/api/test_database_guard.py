"""A guarda dos fixtures destrutivos (conftest.assert_test_database) não pode
ser desligada só por estar dentro do GitHub Actions: o runner self-hosted
também define GITHUB_ACTIONS=true e fica no mesmo host dos bancos reais."""

import pytest

from conftest import assert_test_database


class _Conn:
    def __init__(self, name):
        self.name, self.closed = name, False

    def cursor(self):
        conn = self

        class _Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql):
                pass

            def fetchone(self):
                return (conn.name,)

        return _Cur()

    def close(self):
        self.closed = True


@pytest.mark.parametrize("env", [
    {},
    {"GITHUB_ACTIONS": "true"},
    {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
])
def test_real_database_is_refused_outside_github_hosted_ci(monkeypatch, env):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("RUNNER_ENVIRONMENT", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    conn = _Conn("invariant")
    with pytest.raises(RuntimeError, match="refusing to run destructive"):
        assert_test_database(conn)
    assert conn.closed


def test_github_hosted_service_database_is_allowed(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    assert_test_database(_Conn("invariant")) is None


def test_test_database_is_allowed_anywhere(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("RUNNER_ENVIRONMENT", raising=False)
    assert_test_database(_Conn("invariant_test")) is None
