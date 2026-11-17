"""Tests for deployment migration target validation."""

from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from app.config import Settings
from app.database import migrations
from scripts import validate_release_config


def test_release_config_rejects_non_deployment_environment(monkeypatch):
    settings = Settings(
        _env_file=None,
        APP_ENV="development",
        DATABASE_URL="sqlite:///:memory:",
    )
    monkeypatch.setattr(validate_release_config, "get_settings", lambda: settings)

    with pytest.raises(RuntimeError, match="APP_ENV=staging"):
        validate_release_config.main()


def test_release_config_accepts_postgresql_without_exposing_credentials(monkeypatch):
    settings = Settings(
        _env_file=None,
        APP_ENV="staging",
        DATABASE_URL="postgresql://dbuser:secret@db.example.test:5432/simpati",
    )
    monkeypatch.setattr(validate_release_config, "get_settings", lambda: settings)

    validate_release_config.main()

    summary = validate_release_config.release_configuration_summary(settings)
    assert "DATABASE_DRIVER=postgresql+psycopg" in summary
    assert "secret" not in summary
    assert "db.example.test" not in summary


def test_revision_check_compares_database_with_repository_head(monkeypatch):
    project_root = Path(__file__).resolve().parents[1]
    script = ScriptDirectory.from_config(Config(str(project_root / "alembic.ini")))
    expected_head = script.get_heads()[0]
    test_engine = create_engine("sqlite:///:memory:")
    monkeypatch.setattr(migrations, "engine", test_engine)

    try:
        with test_engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE alembic_version "
                    "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
                )
            )
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": expected_head},
            )

        migrations.verify_database_schema_current()

        with test_engine.begin() as connection:
            connection.execute(
                text("UPDATE alembic_version SET version_num = 'outdated'")
            )

        with pytest.raises(RuntimeError, match="Database migrations are not current"):
            migrations.verify_database_schema_current()
    finally:
        test_engine.dispose()
