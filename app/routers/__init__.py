"""Routers package."""

from app.routers.health import router as health_router
from app.routers.web import router as web_router
from app.routers.api_v1 import api_v1_router

__all__ = ["health_router", "web_router", "api_v1_router"]
