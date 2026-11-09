"""Security, cryptography, and access control package."""

from app.security.hashing import hash_password, verify_password, needs_rehash
from app.security.crypto import (
    generate_ed25519_keypair,
    sign_payload,
    verify_signature,
    generate_secure_token,
    hash_token
)
from app.security.tokens import create_session_token, calculate_session_expiry
from app.security.csrf import (
    generate_csrf_token,
    verify_csrf_token,
    check_csrf_protection,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME
)
from app.security.dependencies import (
    get_current_user,
    require_authenticated_user,
    require_web_user,
    require_superadmin,
    require_csrf,
    get_or_create_csrf_token,
    UnauthenticatedWebUserException
)

__all__ = [
    "hash_password",
    "verify_password",
    "needs_rehash",
    "generate_ed25519_keypair",
    "sign_payload",
    "verify_signature",
    "generate_secure_token",
    "hash_token",
    "create_session_token",
    "calculate_session_expiry",
    "generate_csrf_token",
    "verify_csrf_token",
    "check_csrf_protection",
    "CSRF_COOKIE_NAME",
    "CSRF_HEADER_NAME",
    "get_current_user",
    "require_authenticated_user",
    "require_web_user",
    "require_superadmin",
    "require_csrf",
    "get_or_create_csrf_token",
    "UnauthenticatedWebUserException",
]
