"""Tests for fail-fast database migration behavior during application startup."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


def test_startup_fails_when_database_migration_fails(monkeypatch):
    def fail_migration():
        raise RuntimeError("database migration failed")

    monkeypatch.setattr("app.main.upgrade_database_schema", fail_migration)

    with pytest.raises(RuntimeError, match="database migration failed"):
        with TestClient(app):
            pass
