"""Tests for environment-specific database URL validation."""

import pytest
from pydantic import ValidationError

from app import config
from app.config import Settings


def _capture_database_messages(monkeypatch):
    messages = []
    monkeypatch.setattr(
        config.logger,
        "info",
        lambda template, *args: messages.append(template % args),
    )
    return messages


@pytest.mark.parametrize("app_env", ["staging", "production"])
def test_deployment_environments_reject_missing_database_url(monkeypatch, app_env):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValidationError, match="DATABASE_URL"):
        Settings(_env_file=None, APP_ENV=app_env)


@pytest.mark.parametrize("app_env", ["staging", "production"])
def test_deployment_environments_reject_sqlite_database_url(app_env):
    with pytest.raises(ValidationError, match="DATABASE_URL"):
        Settings(
            _env_file=None,
            APP_ENV=app_env,
            DATABASE_URL="sqlite:///./simpati_license.db",
        )


def test_deployment_environment_accepts_supabase_postgresql_url():
    settings = Settings(
        _env_file=None,
        APP_ENV="staging",
        DATABASE_URL="postgresql://user:password@db.example.test:5432/simpati?sslmode=require",
    )

    assert settings.normalized_database_url.startswith("postgresql+psycopg://")


def test_staging_logs_database_source_and_driver_without_credentials(monkeypatch):
    database_url = (
        "postgresql://dbuser:do-not-log-this@db.example.test:5432/simpati"
        "?sslmode=require"
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    messages = _capture_database_messages(monkeypatch)

    Settings(_env_file=None, APP_ENV="staging")

    message = " ".join(messages)
    assert "APP_ENV=staging" in message
    assert "DATABASE_URL_SOURCE=environment" in message
    assert "DATABASE_DRIVER=postgresql+psycopg" in message
    assert "do-not-log-this" not in message
    assert database_url not in message


def test_staging_logs_sqlite_default_before_rejecting_it(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    messages = _capture_database_messages(monkeypatch)

    with pytest.raises(ValidationError, match="DATABASE_URL"):
        Settings(_env_file=None, APP_ENV="staging")

    message = " ".join(messages)
    assert "DATABASE_URL_SOURCE=default" in message
    assert "DATABASE_DRIVER=sqlite" in message


def test_development_environment_keeps_sqlite_available():
    settings = Settings(
        _env_file=None,
        APP_ENV="development",
        DATABASE_URL="sqlite:///./simpati_license.db",
    )

    assert settings.normalized_database_url == "sqlite:///./simpati_license.db"


def test_engine_uses_shared_settings_and_logs_selected_driver(monkeypatch):
    from app.database import connection

    monkeypatch.delenv("DATABASE_URL", raising=False)
    settings = Settings(
        _env_file=None,
        APP_ENV="staging",
        DATABASE_URL="postgresql://dbuser:do-not-log-this@db.example.test:5432/simpati?sslmode=require",
    )
    monkeypatch.setattr(connection, "settings", settings)
    messages = []
    monkeypatch.setattr(
        connection.logger,
        "info",
        lambda template, *args: messages.append(template % args),
    )

    class TestEngine:
        class dialect:
            name = "postgresql"
            driver = "psycopg"

    created = []

    def create_engine(url, **kwargs):
        created.append(url)
        return TestEngine()

    monkeypatch.setattr(connection, "create_engine", create_engine)

    assert connection.create_db_engine().__class__ is TestEngine
    assert created == [settings.normalized_database_url]
    assert "DIALECT=postgresql DRIVER=psycopg" in messages[0]
    assert "do-not-log-this" not in messages[0]
