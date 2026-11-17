"""Database schema migration helpers."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from app.database.connection import engine


def verify_database_schema_current() -> None:
    """Verify database connectivity and that the release migration reached head."""
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "alembic.ini"))
    script = ScriptDirectory.from_config(config)

    with engine.connect() as connection:
        current_heads = set(MigrationContext.configure(connection).get_current_heads())

    if current_heads != set(script.get_heads()):
        raise RuntimeError(
            "Database migrations are not current. Run `python -m alembic upgrade head` before starting the Web process."
        )


def upgrade_database_schema() -> None:
    """Apply all pending Alembic migrations using the application database engine."""
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "alembic.ini"))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
