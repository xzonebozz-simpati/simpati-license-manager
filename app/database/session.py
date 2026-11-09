"""Database session factory and dependency injection for FastAPI."""

from typing import Generator
from sqlalchemy.orm import sessionmaker, Session
from app.database.connection import engine

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=Session
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to acquire and close database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
