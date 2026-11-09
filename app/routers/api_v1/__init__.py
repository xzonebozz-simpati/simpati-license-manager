"""API v1 routers aggregator."""

from fastapi import APIRouter
from app.routers.api_v1.auth import router as auth_router
from app.routers.api_v1.customers import router as customers_router
from app.routers.api_v1.installations import router as installations_router
from app.routers.api_v1.packages import router as packages_router
from app.routers.api_v1.licenses import router as licenses_router
from app.routers.api_v1.validations import router as validations_router

api_v1_router = APIRouter()
api_v1_router.include_router(auth_router)
api_v1_router.include_router(customers_router)
api_v1_router.include_router(installations_router)
api_v1_router.include_router(packages_router)
api_v1_router.include_router(licenses_router)
api_v1_router.include_router(validations_router)

__all__ = ["api_v1_router"]
