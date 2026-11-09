"""Web frontend router serving Jinja2 HTML templates and handling web authentication."""

from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, Request, Response, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.config import get_settings
from app.database.session import get_db
from app.models.customer import Customer
from app.models.installation import Installation
from app.models.license import License
from app.models.catalog import LicensePackage, ModuleRegistry
from app.models.operations import LicenseValidation, LicenseHistory, LicenseAuditLog, SystemSetting
from app.models.user import LicenseUser
from app.services.license_service import compute_license_status
from app.services.auth_service import authenticate_user, revoke_session
from app.security.dependencies import (
    get_current_user,
    require_web_user,
    get_or_create_csrf_token,
    get_session_token_from_request
)
from app.security.csrf import verify_csrf_token, CSRF_COOKIE_NAME

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
settings = get_settings()

router = APIRouter(include_in_schema=False)


# ==============================================================================
# Authentication & Session Gateways
# ==============================================================================

@router.get("/login", response_class=HTMLResponse)
def view_login(
    request: Request,
    error: Optional[str] = None,
    logout: Optional[str] = None,
    next: Optional[str] = None,
    user: Optional[LicenseUser] = Depends(get_current_user)
):
    """Renders the Superadmin login portal, or redirects to dashboard if already authenticated."""
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    csrf_token = get_or_create_csrf_token(request)
    error_message = None
    info_message = None

    if error:
        error_message = "Nama pengguna atau kata sandi tidak valid. Akses ditolak."
    elif logout:
        info_message = "Anda telah berhasil keluar dari sistem. Sesi aman telah diakhiri."

    response = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "csrf_token": csrf_token,
            "next_url": next or "/",
            "error_message": error_message,
            "info_message": info_message
        }
    )

    # Ensure CSRF token cookie is present
    if not request.cookies.get(CSRF_COOKIE_NAME):
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            httponly=False,
            samesite="lax",
            path="/",
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

    return response


@router.post("/login")
def process_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: Optional[str] = Form(None),
    next: Optional[str] = Form("/"),
    db: Session = Depends(get_db)
):
    """Processes Superadmin login credentials and establishes secure session cookie."""
    # Validate CSRF Token
    cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
    if not verify_csrf_token(csrf_token, cookie_csrf):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "csrf_token": get_or_create_csrf_token(request),
                "next_url": next or "/",
                "error_message": "Sesi formulir kedaluwarsa. Silakan muat ulang halaman dan coba lagi."
            },
            status_code=status.HTTP_403_FORBIDDEN
        )

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    user, token, expires_at = authenticate_user(
        db=db,
        username=username.strip(),
        password=password,
        ip_address=client_ip,
        user_agent=user_agent
    )

    if not user or not token:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "csrf_token": cookie_csrf or get_or_create_csrf_token(request),
                "username": username,
                "next_url": next or "/",
                "error_message": "Nama pengguna atau kata sandi tidak valid."
            },
            status_code=status.HTTP_401_UNAUTHORIZED
        )

    # Valid login: set secure session cookies and redirect to target page
    redirect_target = next if (next and next.startswith("/") and not next.startswith("//")) else "/"
    response = RedirectResponse(url=redirect_target, status_code=status.HTTP_303_SEE_OTHER)

    response.set_cookie(
        key="simpati_session",
        value=token,
        httponly=True,
        samesite="lax",
        path="/",
        secure=settings.is_production,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    # Refresh CSRF token for this authenticated session
    new_csrf = get_or_create_csrf_token(request)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=new_csrf,
        httponly=False,
        samesite="lax",
        path="/",
        secure=settings.is_production,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    return response


@router.get("/logout")
def process_logout(
    request: Request,
    db: Session = Depends(get_db)
):
    """Terminates user session and removes authentication cookies."""
    token = request.cookies.get("simpati_session")
    if token:
        revoke_session(db=db, token=token)

    response = RedirectResponse(url="/login?logout=1", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="simpati_session", path="/")
    return response


# ==============================================================================
# Protected Management Views (All require authenticated Superadmin)
# ==============================================================================

@router.get("/", response_class=HTMLResponse)
def view_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders main dashboard overview with KPI statistics and recent licenses."""
    customers = db.query(Customer).all()
    installations = db.query(Installation).all()
    licenses = db.query(License).order_by(License.created_at.desc()).limit(10).all()
    packages = db.query(LicensePackage).all()
    validations = db.query(LicenseValidation).all()
    recent_audits = db.query(LicenseAuditLog).order_by(LicenseAuditLog.created_at.desc()).limit(5).all()

    for lic in licenses:
        setattr(lic, "computed_status", compute_license_status(lic))

    stats = {
        "total_customers": len(customers),
        "total_installations": len(installations),
        "active_licenses": sum(1 for lic in licenses if getattr(lic, "computed_status", "") == "ACTIVE"),
        "total_validations": len(validations)
    }

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_menu": "dashboard",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "stats": stats,
            "licenses": licenses,
            "customers": customers,
            "packages": packages,
            "recent_audits": recent_audits
        }
    )


@router.get("/customers", response_class=HTMLResponse)
def view_customers(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders customer organizations list."""
    customers = db.query(Customer).order_by(Customer.created_at.desc()).all()
    return templates.TemplateResponse(
        request=request,
        name="customers.html",
        context={
            "active_menu": "customers",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "customers": customers
        }
    )


@router.get("/installations", response_class=HTMLResponse)
def view_installations(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders customer server installations list."""
    installations = db.query(Installation).order_by(Installation.created_at.desc()).all()
    customers = db.query(Customer).order_by(Customer.organization_name.asc()).all()
    return templates.TemplateResponse(
        request=request,
        name="installations.html",
        context={
            "active_menu": "installations",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "installations": installations,
            "customers": customers,
        }
    )


@router.get("/packages", response_class=HTMLResponse)
def view_packages(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders license packages catalog."""
    packages = db.query(LicensePackage).order_by(LicensePackage.created_at.desc()).all()
    all_modules = db.query(ModuleRegistry).order_by(ModuleRegistry.is_core.desc(), ModuleRegistry.module_code.asc()).all()
    return templates.TemplateResponse(
        request=request,
        name="packages.html",
        context={
            "active_menu": "packages",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "packages": packages,
            "all_modules": all_modules
        }
    )


@router.get("/modules", response_class=HTMLResponse)
def view_modules(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders module registry list."""
    modules = db.query(ModuleRegistry).all()
    return templates.TemplateResponse(
        request=request,
        name="modules.html",
        context={
            "active_menu": "modules",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "modules": modules
        }
    )


@router.get("/licenses", response_class=HTMLResponse)
def view_licenses(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders commercial licenses list."""
    licenses = db.query(License).order_by(License.created_at.desc()).all()
    customers = db.query(Customer).order_by(Customer.organization_name.asc()).all()
    packages = db.query(LicensePackage).filter(LicensePackage.is_active == True).order_by(LicensePackage.package_name.asc()).all()
    installations = db.query(Installation).order_by(Installation.name.asc()).all()
    all_modules = db.query(ModuleRegistry).order_by(ModuleRegistry.is_core.desc(), ModuleRegistry.module_code.asc()).all()

    for lic in licenses:
        setattr(lic, "computed_status", compute_license_status(lic))

    return templates.TemplateResponse(
        request=request,
        name="licenses.html",
        context={
            "active_menu": "licenses",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "licenses": licenses,
            "customers": customers,
            "packages": packages,
            "installations": installations,
            "all_modules": all_modules
        }
    )


@router.get("/validations", response_class=HTMLResponse)
def view_validations(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders license validation logs."""
    validations = db.query(LicenseValidation).order_by(LicenseValidation.validated_at.desc()).limit(100).all()
    return templates.TemplateResponse(
        request=request,
        name="validations.html",
        context={
            "active_menu": "validations",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "validations": validations
        }
    )


@router.get("/history", response_class=HTMLResponse)
def view_history(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders license lifecycle transitions history."""
    history = db.query(LicenseHistory).order_by(LicenseHistory.created_at.desc()).limit(100).all()
    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={
            "active_menu": "history",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "history": history
        }
    )


@router.get("/audit", response_class=HTMLResponse)
def view_audit(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders administrative audit logs."""
    audit_logs = db.query(LicenseAuditLog).order_by(LicenseAuditLog.created_at.desc()).limit(100).all()
    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            "active_menu": "audit",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "audit_logs": audit_logs
        }
    )


@router.get("/settings", response_class=HTMLResponse)
def view_settings(
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_web_user)
):
    """Renders system configuration and cryptographic keys overview."""
    settings_list = db.query(SystemSetting).all()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "active_menu": "settings",
            "current_user": current_user,
            "csrf_token": get_or_create_csrf_token(request),
            "settings_list": settings_list
        }
    )
