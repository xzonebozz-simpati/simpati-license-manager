"""FastAPI security dependencies for authentication, authorization, and CSRF protection."""

from datetime import datetime, timezone
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import LicenseUser, LicenseUserSession
from app.security.crypto import hash_token
from app.security.csrf import check_csrf_protection, generate_csrf_token, CSRF_COOKIE_NAME

bearer_scheme = HTTPBearer(auto_error=False)


class UnauthenticatedWebUserException(Exception):
    """Exception raised when an unauthenticated user attempts to access protected web pages."""
    def __init__(self, next_url: str = "/"):
        self.next_url = next_url


def get_session_token_from_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> Optional[str]:
    """Extracts session token from Bearer header or cookie."""
    if credentials and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    # Fallback to cookie
    return request.cookies.get("simpati_session")


def get_current_user(
    token: Optional[str] = Depends(get_session_token_from_request),
    db: Session = Depends(get_db)
) -> Optional[LicenseUser]:
    """Resolves authenticated user from session token."""
    if not token:
        return None

    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)

    session_record = db.query(LicenseUserSession).filter(
        LicenseUserSession.session_token_hash == token_hash,
        LicenseUserSession.revoked_at.is_(None),
        LicenseUserSession.expires_at > now
    ).first()

    if not session_record:
        return None

    user = db.query(LicenseUser).filter(
        LicenseUser.id == session_record.user_id,
        LicenseUser.is_active == True
    ).first()

    return user


def require_authenticated_user(
    user: Optional[LicenseUser] = Depends(get_current_user)
) -> LicenseUser:
    """Enforces that an API user is authenticated."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi diperlukan. Sesi tidak valid atau telah berakhir.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


def require_web_user(
    request: Request,
    user: Optional[LicenseUser] = Depends(get_current_user)
) -> LicenseUser:
    """Enforces that a web dashboard visitor is authenticated, redirecting to login if not."""
    if not user:
        raise UnauthenticatedWebUserException(next_url=request.url.path)
    if user.role != "SUPERADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses dashboard memerlukan hak License Superadmin."
        )
    return user


def require_superadmin(
    user: LicenseUser = Depends(require_authenticated_user)
) -> LicenseUser:
    """Enforces that the authenticated user possesses SUPERADMIN role."""
    if user.role != "SUPERADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses ditolak. Tindakan ini memerlukan hak License Superadmin."
        )
    return user


async def require_csrf(request: Request) -> bool:
    """Dependency that triggers CSRF validation on mutating requests."""
    return await check_csrf_protection(request)


def get_or_create_csrf_token(request: Request) -> str:
    """Retrieves current CSRF token from cookie or generates a new one."""
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if not token:
        token = generate_csrf_token()
    return token


# ---------------------------------------------------------------------------
# M2M Installation Authentication (HTTP Basic)
# ---------------------------------------------------------------------------

from fastapi.security import HTTPBasic, HTTPBasicCredentials
from app.models.installation import Installation, InstallationCredential
from app.security.hashing import verify_password

basic_scheme = HTTPBasic(auto_error=False)


def require_installation_auth(
    credentials: Optional[HTTPBasicCredentials] = Depends(basic_scheme),
    db: Session = Depends(get_db)
) -> Installation:
    """
    Enforces M2M HTTP Basic Authentication for installation requests.
    Validates client_id and client_secret against active installation_credentials using Argon2id.
    Returns the authenticated Installation ORM object.
    """
    if not credentials or not credentials.username or not credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi instalasi M2M diperlukan (HTTP Basic Auth).",
            headers={"WWW-Authenticate": "Basic"}
        )

    client_id = credentials.username.strip()
    client_secret = credentials.password

    # Query active credential matching client_id
    cred = (
        db.query(InstallationCredential)
        .filter(
            InstallationCredential.client_id == client_id,
            InstallationCredential.is_active == True,
            InstallationCredential.revoked_at.is_(None)
        )
        .first()
    )

    if not cred or not verify_password(client_secret, cred.client_secret_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kredensial instalasi (Client ID / Client Secret) tidak valid atau telah dicabut.",
            headers={"WWW-Authenticate": "Basic"}
        )

    installation = (
        db.query(Installation)
        .filter(
            Installation.id == cred.installation_id,
            Installation.status == "ACTIVE"
        )
        .first()
    )

    if not installation:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Instalasi yang terikat dengan kredensial ini tidak aktif atau tidak ditemukan."
        )

    return installation
