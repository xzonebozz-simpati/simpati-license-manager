"""Health check and diagnostic endpoints for Load Balancers, Hostless, and Monitoring."""

from datetime import datetime, timezone
from fastapi import APIRouter, status, Response
from app.config import get_settings
from app.database.connection import check_db_connection
from app.models.base import Base
from app.schemas.health import HealthResponse, DatabaseHealthResponse

router = APIRouter(tags=["Health Diagnostics"])
settings = get_settings()


@router.get("/healthz", response_model=HealthResponse, summary="App Health Check (Liveness)")
@router.get("/health", response_model=HealthResponse, summary="App Health Check (Alias for Cloud/Hostless)")
@router.get("/api/v1/health", response_model=HealthResponse, summary="API v1 Health Check")
def healthz():
    """Liveness probe returning application metadata and operational state."""
    return HealthResponse(
        status="ok",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        timestamp=datetime.now(timezone.utc)
    )


@router.get("/api/v1/health/db", response_model=DatabaseHealthResponse, summary="Database Connection Check (Readiness)")
def database_health(response: Response):
    """Verifies live PostgreSQL / Supabase connectivity and records round-trip latency."""
    db_result = check_db_connection()
    status_code = status.HTTP_200_OK if db_result["status"] == "connected" else status.HTTP_503_SERVICE_UNAVAILABLE
    response.status_code = status_code

    return DatabaseHealthResponse(
        status=db_result["status"],
        dialect=db_result["dialect"],
        latency_ms=db_result["latency_ms"],
        tables_registered=len(Base.metadata.tables),
        error=db_result["error"],
        timestamp=datetime.now(timezone.utc)
    )
