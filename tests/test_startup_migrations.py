"""Tests for fail-fast database migration behavior during application startup."""

import pytest
from fastapi.testclient import TestClient
from uvicorn.importer import import_from_string

from app.main import app


def test_legacy_uvicorn_target_resolves_fastapi_application():
    assert import_from_string("app:app") is app


def test_startup_fails_when_database_migration_fails(monkeypatch):
    def fail_migration():
        raise RuntimeError("database migration failed")

    monkeypatch.setattr("app.main.upgrade_database_schema", fail_migration)

    with pytest.raises(RuntimeError, match="database migration failed"):
        with TestClient(app):
            pass


def test_production_startup_verifies_database_without_migrating_or_seeding(monkeypatch):
    verified = []
    monkeypatch.setattr("app.main.settings.APP_ENV", "staging")
    monkeypatch.setattr(
        "app.main.verify_database_schema_current",
        lambda: verified.append(True),
    )
    monkeypatch.setattr(
        "app.main.upgrade_database_schema",
        lambda: pytest.fail("production startup must not run migrations"),
    )
    monkeypatch.setattr(
        "app.main.seed_initial_data",
        lambda: pytest.fail("production startup must not seed data"),
    )

    with TestClient(app):
        pass

    assert verified == [True]
