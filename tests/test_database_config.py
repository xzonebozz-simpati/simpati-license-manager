"""Tests for environment-specific database URL validation."""

import pytest
from pydantic import ValidationError

from app.config import Settings


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


def test_development_environment_keeps_sqlite_available():
    settings = Settings(
        _env_file=None,
        APP_ENV="development",
        DATABASE_URL="sqlite:///./simpati_license.db",
    )

    assert settings.normalized_database_url == "sqlite:///./simpati_license.db"
