"""Database engine and connectivity check module.

Optimized for Supabase PostgreSQL (direct connection or PgBouncer transaction pooler)
as well as SQLite for local test suites.
"""

import time
import logging
from typing import Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger("simpati.database")


def create_db_engine() -> Engine:
    """Creates and configures the SQLAlchemy engine based on configuration."""
    db_url = settings.normalized_database_url

    connect_args: Dict[str, Any] = {}
    engine_kwargs: Dict[str, Any] = {
        "pool_pre_ping": True,
        "echo": False,
    }

    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        engine_kwargs["connect_args"] = connect_args
        if ":memory:" in db_url:
            from sqlalchemy.pool import StaticPool
            engine_kwargs["poolclass"] = StaticPool
    else:
        # PostgreSQL / Supabase settings
        # Ensure sslmode=require for secure cloud communication with Supabase
        if "sslmode" not in db_url.lower():
            connect_args["sslmode"] = "require"

        engine_kwargs["connect_args"] = connect_args
        engine_kwargs.update({
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_timeout": settings.DB_POOL_TIMEOUT,
            "pool_recycle": settings.DB_POOL_RECYCLE,
        })

    db_engine = create_engine(db_url, **engine_kwargs)
    logger.info(
        "SQLAlchemy engine initialized: APP_ENV=%s DATABASE_URL_SOURCE=%s DIALECT=%s DRIVER=%s",
        settings.APP_ENV,
        settings.database_url_source,
        db_engine.dialect.name,
        db_engine.dialect.driver,
    )
    return db_engine


engine = create_db_engine()


def check_db_connection() -> Dict[str, Any]:
    """Tests the database connection and measures response latency."""
    start_time = time.perf_counter()
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.scalar()
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "connected",
            "dialect": engine.dialect.name,
            "latency_ms": elapsed_ms,
            "error": None
        }
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "error",
            "dialect": engine.dialect.name if hasattr(engine, "dialect") else "unknown",
            "latency_ms": elapsed_ms,
            "error": str(exc)
        }
