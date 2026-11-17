"""Database schema migration helpers."""

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text

from app.config import get_settings
from app.database.connection import engine

logger = logging.getLogger("simpati.database")


def verify_database_schema_current() -> None:
    """Verify database connectivity and that the release migration reached head."""
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "alembic.ini"))
    script = ScriptDirectory.from_config(config)
    expected_heads = set(script.get_heads())

    with engine.connect() as connection:
        current_heads = set(MigrationContext.configure(connection).get_current_heads())
        if engine.dialect.name == "postgresql":
            database, schema = connection.execute(
                text("SELECT current_database(), current_schema()")
            ).one()
        else:
            database, schema = "n/a", "n/a"

    settings = get_settings()
    logger.info(
        "Alembic revision check: APP_ENV=%s DATABASE_URL_SOURCE=%s "
        "DIALECT=%s DRIVER=%s DATABASE=%s SCHEMA=%s CURRENT_HEADS=%s REPOSITORY_HEADS=%s",
        settings.APP_ENV,
        settings.database_url_source,
        engine.dialect.name,
        engine.dialect.driver,
        database,
        schema,
        sorted(current_heads),
        sorted(expected_heads),
    )

    if current_heads != expected_heads:
        raise RuntimeError(
            "Database migrations are not current "
            f"(database={sorted(current_heads)}, repository={sorted(expected_heads)}). "
            "Run `python -m alembic upgrade head` before starting the Web process."
        )


def upgrade_database_schema() -> None:
    """Apply all pending Alembic migrations using the application database engine."""
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "alembic.ini"))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
