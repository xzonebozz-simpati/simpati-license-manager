"""Package catalog management API endpoints."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.catalog import LicensePackage, ModuleRegistry
from app.models.user import LicenseUser
from app.schemas.package import (
    PackageCreate,
    PackageUpdate,
    PackageResponse,
    PackageDetailResponse,
)
from app.services.package_service import (
    get_all_packages,
    get_package_by_id,
    create_package,
    update_package,
    set_package_status,
    get_package_detail,
)
from app.security.dependencies import require_authenticated_user

router = APIRouter(prefix="/api/v1/packages", tags=["Packages"])


@router.get("", response_model=List[PackageResponse], summary="List Packages")
def list_packages_endpoint(
    is_active: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user)
):
    """Retrieves all commercial packages with optional active filter."""
    query = db.query(LicensePackage)
    if is_active is not None:
        query = query.filter(LicensePackage.is_active == is_active)
    packages = query.order_by(LicensePackage.created_at.desc()).offset(skip).limit(limit).all()

    results = []
    for p in packages:
        modules = [pm.module.module_code for pm in p.package_modules if pm.module]
        results.append(PackageResponse(
            id=p.id,
            package_code=p.package_code,
            package_name=p.package_name,
            description=p.description,
            default_tier=p.default_tier,
            is_active=p.is_active,
            created_at=p.created_at,
            updated_at=p.updated_at,
            modules=modules,
            total_licenses=len(p.licenses) if p.licenses else 0
        ))
    return results


@router.get("/modules/available", summary="List Available Modules Registry")
def list_available_modules(
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user)
):
    """Returns all functional application modules available for package bundling."""
    modules = db.query(ModuleRegistry).order_by(ModuleRegistry.is_core.desc(), ModuleRegistry.module_code.asc()).all()
    return [
        {
            "id": str(m.id),
            "module_code": m.module_code,
            "module_name": m.module_name,
            "description": m.description,
            "is_core": m.is_core,
            "is_active": m.is_active
        }
        for m in modules
    ]


@router.post("", response_model=PackageResponse, status_code=status.HTTP_201_CREATED, summary="Create Package")
def create_package_endpoint(
    payload: PackageCreate,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Creates a new commercial license package."""
    try:
        package = create_package(db=db, data=payload, user_id=current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    modules = [pm.module.module_code for pm in package.package_modules if pm.module]
    return PackageResponse(
        id=package.id,
        package_code=package.package_code,
        package_name=package.package_name,
        description=package.description,
        default_tier=package.default_tier,
        is_active=package.is_active,
        created_at=package.created_at,
        updated_at=package.updated_at,
        modules=modules,
        total_licenses=0
    )


@router.get("/{package_id}/detail", response_model=PackageDetailResponse, summary="Get Package Detail")
@router.get("/{package_id}", response_model=PackageDetailResponse, summary="Get Package by ID")
def get_package_endpoint(
    package_id: UUID,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user)
):
    """Retrieves full package specification, modules, and commercial configurations."""
    detail = get_package_detail(db, package_id)
    if not detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Paket lisensi tidak ditemukan.")
    return detail


@router.put("/{package_id}", response_model=PackageResponse, summary="Update Package")
def update_package_endpoint(
    package_id: UUID,
    payload: PackageUpdate,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Updates attributes of an existing package."""
    updated = update_package(db=db, package_id=package_id, data=payload, user_id=current_user.id)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Paket lisensi tidak ditemukan.")

    modules = [pm.module.module_code for pm in updated.package_modules if pm.module]
    return PackageResponse(
        id=updated.id,
        package_code=updated.package_code,
        package_name=updated.package_name,
        description=updated.description,
        default_tier=updated.default_tier,
        is_active=updated.is_active,
        created_at=updated.created_at,
        updated_at=updated.updated_at,
        modules=modules,
        total_licenses=len(updated.licenses) if updated.licenses else 0
    )


@router.patch("/{package_id}/status", response_model=PackageResponse, summary="Toggle Package Status")
def set_status_endpoint(
    package_id: UUID,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Activates or deactivates a package."""
    is_active = bool(payload.get("is_active", True))
    package = set_package_status(db=db, package_id=package_id, is_active=is_active, user_id=current_user.id)
    if not package:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Paket lisensi tidak ditemukan.")

    modules = [pm.module.module_code for pm in package.package_modules if pm.module]
    return PackageResponse(
        id=package.id,
        package_code=package.package_code,
        package_name=package.package_name,
        description=package.description,
        default_tier=package.default_tier,
        is_active=package.is_active,
        created_at=package.created_at,
        updated_at=package.updated_at,
        modules=modules,
        total_licenses=len(package.licenses) if package.licenses else 0
    )
