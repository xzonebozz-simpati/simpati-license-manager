"""CSRF (Cross-Site Request Forgery) protection module."""

import secrets
from typing import Optional
from fastapi import Request, HTTPException, status

CSRF_COOKIE_NAME = "simpati_csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"


def generate_csrf_token() -> str:
    """Generates a cryptographically strong random CSRF token."""
    return f"csrf_{secrets.token_urlsafe(32)}"


def verify_csrf_token(provided_token: Optional[str], expected_token: Optional[str]) -> bool:
    """Safely compares two CSRF tokens using constant-time comparison."""
    if not provided_token or not expected_token:
        return False
    return secrets.compare_digest(provided_token, expected_token)


async def check_csrf_protection(request: Request) -> bool:
    """Validates CSRF token on state-modifying HTTP methods.

    Safe methods (GET, HEAD, OPTIONS) and machine-to-machine endpoints
    (like /api/v1/validations/verify) are exempted.
    """
    if request.method in ["GET", "HEAD", "OPTIONS"]:
        return True

    # Exempt machine-to-machine endpoints that use cryptographic signatures or telemetry
    exempt_paths = [
        "/api/v1/validations/verify",
        "/api/v1/installations/heartbeat",
        "/api/v1/auth/login",
    ]
    if any(request.url.path.startswith(p) for p in exempt_paths):
        return True

    # If the request is authenticated solely via Bearer token (no session cookie),
    # CSRF protection is not required because browsers do not send Bearer tokens automatically
    has_session_cookie = bool(request.cookies.get("simpati_session"))
    auth_header = request.headers.get("Authorization", "")
    if not has_session_cookie and auth_header.startswith("Bearer "):
        return True

    # For browser session requests, verify CSRF token
    expected_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not expected_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Validasi CSRF gagal: Cookie token CSRF tidak ditemukan."
        )

    # Check header first
    provided_token = request.headers.get(CSRF_HEADER_NAME)

    # Check form body if not in header
    if not provided_token:
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            try:
                form = await request.form()
                provided_token = form.get("csrf_token")
            except Exception:
                provided_token = None

    if not verify_csrf_token(provided_token, expected_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Validasi CSRF gagal: Token CSRF tidak valid atau tidak cocok."
        )

    return True
