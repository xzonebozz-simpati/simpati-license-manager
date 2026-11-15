"""Health check and diagnostic response schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """General application health check schema."""
    status: str = Field(..., json_schema_extra={"example": "ok"})
    app: str = Field(..., json_schema_extra={"example": "SIMPATI License Manager"})
    version: str = Field(..., json_schema_extra={"example": "1.0.0"})
    environment: str = Field(..., json_schema_extra={"example": "development"})
    timestamp: datetime


class DatabaseHealthResponse(BaseModel):
    """Database connectivity and engine diagnostic schema."""
    status: str = Field(..., json_schema_extra={"example": "connected"})
    dialect: str = Field(..., json_schema_extra={"example": "postgresql"})
    latency_ms: float = Field(..., json_schema_extra={"example": 1.45})
    tables_registered: int = Field(..., json_schema_extra={"example": 24})
    error: Optional[str] = None
    timestamp: datetime
