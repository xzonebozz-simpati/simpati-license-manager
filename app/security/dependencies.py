"""FastAPI security dependencies for authentication, authorization, and CSRF protection."""

from dataclasses import dataclass
from datetime import datetime, timezone
from hmac import compare_digest
from typing import Optional
from uuid import UUID
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.config import get_settings
from app.database.session import get_db
from app.models.user import LicenseUser, LicenseUserSession
from app.security.crypto import hash_token
from app.security.csrf import check_csrf_protection, generate_csrf_token, CSRF_COOKIE_NAME
from app.services.audit_service import log_audit_event

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


@dataclass(frozen=True)
class LicenseApiPrincipal:
    user_id: Optional[UUID] = None
    service_id: Optional[str] = None


class ServiceAuthenticationConfigurationError(ValueError):
    pass


def _universal_api_service_credentials() -> Optional[tuple[str, tuple[str, ...]]]:
    settings = get_settings()
    service_id = (settings.UNIVERSAL_API_SERVICE_ID or "").strip()
    current_field = settings.UNIVERSAL_API_SERVICE_SECRET
    previous_field = settings.UNIVERSAL_API_SERVICE_PREVIOUS_SECRET
    current_secret = (
        current_field.get_secret_value() if current_field is not None else ""
    )
    previous_secret = (
        previous_field.get_secret_value() if previous_field is not None else ""
    )

    if not service_id and not current_secret and not previous_secret:
        return None
    if (
        not service_id
        or len(service_id) > 64
        or not service_id.isascii()
        or any(
            not (character.isalnum() or character in "._-")
            for character in service_id
        )
        or len(current_secret.encode("utf-8")) < 32
    ):
        raise ServiceAuthenticationConfigurationError(
            "Universal API service credentials are incomplete or invalid."
        )

    secrets = [current_secret]
    if previous_secret:
        if (
            len(previous_secret.encode("utf-8")) < 32
            or compare_digest(
                previous_secret.encode("utf-8"),
                current_secret.encode("utf-8"),
            )
        ):
            raise ServiceAuthenticationConfigurationError(
                "Universal API service credentials are incomplete or invalid."
            )
        secrets.append(previous_secret)
    return service_id, tuple(secrets)


def validate_universal_api_service_configuration() -> None:
    _universal_api_service_credentials()


def _service_scope_allows(request: Request) -> bool:
    method = request.method.upper()
    path = request.url.path
    if method == "GET" and path in {
        "/api/v1/customers",
        "/api/v1/packages",
        "/api/v1/packages/modules/available",
        "/api/v1/licenses",
    }:
        return True
    if method == "POST" and path == "/api/v1/licenses":
        return True

    segments = path.strip("/").split("/")
    if segments[:3] == ["api", "v1", "packages"] and method == "GET":
        if len(segments) == 4:
            try:
                UUID(segments[3])
                return True
            except ValueError:
                return False
        if len(segments) == 5 and segments[4] == "detail":
            try:
                UUID(segments[3])
                return True
            except ValueError:
                return False
        return False

    if segments[:3] != ["api", "v1", "licenses"]:
        return False
    if method == "GET" and len(segments) == 4:
        try:
            UUID(segments[3])
            return True
        except ValueError:
            return False
    if method == "GET" and len(segments) == 5 and segments[4] == "detail":
        try:
            UUID(segments[3])
            return True
        except ValueError:
            return False
    return False


def require_license_api_principal(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(basic_scheme),
    user: Optional[LicenseUser] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> LicenseApiPrincipal:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("basic "):
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kredensial layanan tidak valid.",
                headers={"WWW-Authenticate": "Basic"},
            )
        try:
            configured = _universal_api_service_credentials()
        except ServiceAuthenticationConfigurationError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Autentikasi layanan Universal API tidak dikonfigurasi dengan benar.",
            ) from None
        if configured is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Autentikasi layanan Universal API belum dikonfigurasi.",
            )

        service_id, allowed_secrets = configured
        username_matches = compare_digest(
            credentials.username.encode("utf-8"),
            service_id.encode("utf-8"),
        )
        supplied_secret = credentials.password.encode("utf-8")
        secret_matches = False
        for allowed_secret in allowed_secrets:
            secret_matches |= compare_digest(
                supplied_secret,
                allowed_secret.encode("utf-8"),
            )
        if not username_matches or not secret_matches:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kredensial layanan tidak valid.",
                headers={"WWW-Authenticate": "Basic"},
            )
        if not _service_scope_allows(request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operasi ini tidak diizinkan untuk layanan Universal API.",
            )

        log_audit_event(
            db=db,
            action_category="AUTH",
            action_name="SERVICE_REQUEST_AUTHORIZED",
            ip_address=request.client.host if request.client else None,
            target_resource=f"{request.method} {request.url.path}",
            details={"service_id": service_id},
            status="SUCCESS",
        )
        return LicenseApiPrincipal(service_id=service_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi diperlukan. Sesi tidak valid atau telah berakhir.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.role != "SUPERADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses ditolak. Tindakan ini memerlukan hak License Superadmin.",
        )
    return LicenseApiPrincipal(user_id=user.id)
