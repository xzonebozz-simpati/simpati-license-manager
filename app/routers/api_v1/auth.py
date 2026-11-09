"""Authentication and session management API router."""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session
from app.config import get_settings
from app.database.session import get_db
from app.schemas.auth import LoginRequest, LoginResponse, UserResponse
from app.services.auth_service import authenticate_user, revoke_session
from app.security.dependencies import require_authenticated_user, get_session_token_from_request
from app.security.csrf import generate_csrf_token, CSRF_COOKIE_NAME
from app.models.user import LicenseUser

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
settings = get_settings()


@router.post("/login", response_model=LoginResponse, summary="License Manager User Login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """Authenticates superadmin/operator and issues a session token."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    user, token, expires_at = authenticate_user(
        db=db,
        username=payload.username.strip(),
        password=payload.password,
        ip_address=client_ip,
        user_agent=user_agent
    )

    if not user or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nama pengguna atau kata sandi tidak valid."
        )

    # Set secure session cookie
    response.set_cookie(
        key="simpati_session",
        value=token,
        httponly=True,
        samesite="lax",
        path="/",
        secure=settings.is_production,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    # Set CSRF token cookie
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        samesite="lax",
        path="/",
        secure=settings.is_production,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    return LoginResponse(
        access_token=token,
        expires_at=expires_at,
        user_id=user.id,
        username=user.username,
        full_name=user.full_name,
        role=user.role
    )


@router.post("/logout", summary="Logout and Revoke Session")
def logout(
    response: Response,
    token: str = Depends(get_session_token_from_request),
    db: Session = Depends(get_db)
):
    """Terminates active session."""
    if token:
        revoke_session(db=db, token=token)
    response.delete_cookie(key="simpati_session", path="/")
    response.delete_cookie(key=CSRF_COOKIE_NAME, path="/")
    return {"message": "Sesi berhasil diakhiri."}


@router.get("/me", response_model=UserResponse, summary="Get Current Authenticated User")
def get_current_profile(user: LicenseUser = Depends(require_authenticated_user)):
    """Retrieves profile of currently logged-in user."""
    return user
