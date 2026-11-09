"""Authentication service for managing user logins, sessions, and credentials."""

from datetime import datetime, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from app.models.user import LicenseUser, LicenseUserSession
from app.security.hashing import verify_password
from app.security.tokens import create_session_token, calculate_session_expiry
from app.security.crypto import hash_token
from app.services.audit_service import log_audit_event


def authenticate_user(
    db: Session,
    username: str,
    password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Tuple[Optional[LicenseUser], Optional[str], Optional[datetime]]:
    """Authenticates a user and creates an active session.

    Returns (user, raw_token, expires_at) on success, or (None, None, None) on failure.
    """
    user = db.query(LicenseUser).filter(LicenseUser.username == username).first()
    if not user or not user.is_active:
        log_audit_event(
            db=db,
            action_category="AUTH",
            action_name="LOGIN_FAILED",
            ip_address=ip_address,
            target_resource=f"user:{username}",
            details={"reason": "User not found or inactive"},
            status="FAILURE"
        )
        return None, None, None

    if not verify_password(password, user.password_hash):
        log_audit_event(
            db=db,
            action_category="AUTH",
            action_name="LOGIN_FAILED",
            user_id=user.id,
            ip_address=ip_address,
            target_resource=f"user:{username}",
            details={"reason": "Invalid password credentials"},
            status="FAILURE"
        )
        return None, None, None

    # Update last login
    user.last_login_at = datetime.now(timezone.utc)

    # Issue new session
    raw_token = create_session_token()
    token_hash = hash_token(raw_token)
    expires_at = calculate_session_expiry()

    session_record = LicenseUserSession(
        user_id=user.id,
        session_token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at
    )
    db.add(session_record)
    db.commit()

    log_audit_event(
        db=db,
        action_category="AUTH",
        action_name="LOGIN_SUCCESS",
        user_id=user.id,
        ip_address=ip_address,
        target_resource=f"user:{user.username}",
        details={"role": user.role, "expires_at": expires_at.isoformat()},
        status="SUCCESS"
    )

    return user, raw_token, expires_at


def revoke_session(db: Session, token: str, user_id: Optional[str] = None) -> bool:
    """Revokes an active session token."""
    token_hash = hash_token(token)
    session_record = db.query(LicenseUserSession).filter(
        LicenseUserSession.session_token_hash == token_hash,
        LicenseUserSession.revoked_at.is_(None)
    ).first()

    if session_record:
        session_record.revoked_at = datetime.now(timezone.utc)
        db.commit()
        log_audit_event(
            db=db,
            action_category="AUTH",
            action_name="LOGOUT",
            user_id=session_record.user_id,
            target_resource="session",
            status="SUCCESS"
        )
        return True
    return False
