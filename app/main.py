"""FastAPI application factory, lifespan handler, exception handlers, and security middleware."""

import logging
import hashlib
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy import inspect, text
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.config import get_settings
from app.database.connection import engine
from app.models.base import Base
from app.routers import health_router, web_router, api_v1_router
from app.security import (
    UnauthenticatedWebUserException,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    verify_csrf_token
)
from scripts.init_db import seed_initial_data

def _compute_static_version() -> str:
    """Hitung hash MD5 dari app.js untuk cache busting otomatis."""
    try:
        js_path = Path(__file__).resolve().parent / "static" / "js" / "app.js"
        return hashlib.md5(js_path.read_bytes()).hexdigest()[:8]
    except Exception:
        import time
        return str(int(time.time()))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("simpati.app")
settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan event handler for startup and graceful shutdown."""
    logger.info("Memulai SIMPATI License Manager...")
    try:
        # Create missing tables first. SQLAlchemy create_all() does not add
        # newly introduced columns to tables that already exist.
        Base.metadata.create_all(bind=engine)

        inspector = inspect(engine)
        if inspector.has_table("package_modules"):
            columns = {column["name"] for column in inspector.get_columns("package_modules")}
            if "is_mandatory" not in columns:
                logger.warning(
                    "Kolom package_modules.is_mandatory belum ada; menjalankan kompatibilitas skema."
                )
                with engine.begin() as connection:
                    connection.execute(text(
                        "ALTER TABLE package_modules "
                        "ADD COLUMN is_mandatory BOOLEAN NOT NULL DEFAULT TRUE"
                    ))
                logger.info("Kolom package_modules.is_mandatory berhasil ditambahkan.")

        # Verify the column before any ORM query/seeding uses it.
        verified_columns = {
            column["name"] for column in inspect(engine).get_columns("package_modules")
        }
        if "is_mandatory" not in verified_columns:
            raise RuntimeError(
                "Skema database belum kompatibel: package_modules.is_mandatory tidak tersedia."
            )

        logger.info("Skema database terverifikasi.")
        seed_initial_data()
        logger.info("Inisialisasi database dan seeding data awal berhasil.")
    except Exception:
        logger.exception(
            "Inisialisasi database gagal. Startup tetap berjalan, tetapi fitur database "
            "mungkin tidak tersedia sampai masalah skema/koneksi diperbaiki."
        )

    yield

    logger.info("Menghentikan SIMPATI License Manager...")


def create_application() -> FastAPI:
    """Creates and configures the FastAPI application instance."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Sistem Pusat Pengelolaan Lisensi Komersial untuk SIMPATI 555",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc"
    )

    # Reverse Proxy Headers Middleware (Essential for Hostless / Cloudflare SSL termination)
    app.add_middleware(
        ProxyHeadersMiddleware,
        trusted_hosts=settings.FORWARDED_ALLOW_IPS
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # CSRF Protection Middleware for browser session requests
    @app.middleware("http")
    async def csrf_protection_middleware(request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            exempt_paths = [
                "/api/v1/validations/verify",
                "/api/v1/validations/preview",
                "/api/v1/installations/heartbeat",
                "/api/v1/auth/login",
                "/login"
            ]
            if not any(request.url.path.startswith(p) for p in exempt_paths):
                # If request has browser session cookie, enforce CSRF token header
                if request.cookies.get("simpati_session"):
                    expected_csrf = request.cookies.get(CSRF_COOKIE_NAME)
                    provided_csrf = request.headers.get(CSRF_HEADER_NAME)
                    if not expected_csrf or not verify_csrf_token(provided_csrf, expected_csrf):
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={"detail": "Validasi CSRF gagal: Token CSRF tidak valid atau tidak cocok."}
                        )
        return await call_next(request)

    # Handler to redirect unauthenticated web visitors to /login
    @app.exception_handler(UnauthenticatedWebUserException)
    async def unauthenticated_web_user_handler(request: Request, exc: UnauthenticatedWebUserException):
        target = f"/login?next={exc.next_url}" if exc.next_url and exc.next_url != "/" else "/login"
        return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)

    # Mount static assets
    static_path = BASE_DIR / "static"
    if static_path.exists():
        app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

    # Inject app_version global ke semua Jinja2 templates untuk cache busting
    from app.routers.web import templates
    templates.env.globals["app_version"] = _compute_static_version()

    # Include Routers
    app.include_router(health_router)
    app.include_router(web_router)
    app.include_router(api_v1_router)

    return app


app = create_application()
