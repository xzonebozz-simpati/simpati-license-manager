"""Database schema migration helpers."""

from pathlib import Path

from alembic import command
from alembic.config import Config

from app.database.connection import engine


def upgrade_database_schema() -> None:
    """Apply all pending Alembic migrations using the application database engine."""
    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "alembic.ini"))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
