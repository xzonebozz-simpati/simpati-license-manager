"""Session and authentication token utilities."""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from app.config import get_settings
from app.security.crypto import hash_token

settings = get_settings()


def create_session_token() -> str:
    """Generates an opaque high-entropy session token."""
    return f"smp_sess_{secrets.token_urlsafe(48)}"


def calculate_session_expiry(minutes: Optional[int] = None) -> datetime:
    """Calculates UTC expiration timestamp for a session."""
    expire_minutes = minutes if minutes is not None else settings.ACCESS_TOKEN_EXPIRE_MINUTES
    return datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
