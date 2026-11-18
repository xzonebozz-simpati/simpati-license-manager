"""Tests for the controlled deployment startup command."""

from subprocess import CompletedProcess

import pytest

from scripts import start_web


def test_start_web_runs_migrations_before_uvicorn(monkeypatch):
    events = []

    def run_migrations():
        events.append("migrations")

    def run_server(command, **kwargs):
        events.append(("server", command, kwargs))
        return CompletedProcess(command, 0)

    monkeypatch.setattr(start_web, "run_release_migrations", run_migrations)
    monkeypatch.setattr(start_web.subprocess, "run", run_server)
    monkeypatch.setenv("PORT", "9000")

    with pytest.raises(SystemExit) as exc_info:
        start_web.main()

    assert exc_info.value.code == 0
    assert events[0] == "migrations"
    assert events[1][0] == "server"
    assert events[1][1][0:4] == [
        start_web.sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
    ]
    assert events[1][1][events[1][1].index("--port") + 1] == "9000"
    assert events[1][2] == {"check": False}


def test_start_web_does_not_start_uvicorn_when_migrations_fail(monkeypatch):
    def fail_migrations():
        raise SystemExit(3)

    monkeypatch.setattr(start_web, "run_release_migrations", fail_migrations)
    monkeypatch.setattr(
        start_web.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("Uvicorn must not start"),
    )

    with pytest.raises(SystemExit) as exc_info:
        start_web.main()

    assert exc_info.value.code == 3
