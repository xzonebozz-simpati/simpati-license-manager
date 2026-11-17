"""Customer management API endpoints."""

from typing import List, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.schemas.customer import (
    CustomerCreate,
    CustomerUpdate,
    CustomerStatusUpdate,
    CustomerResponse,
    CustomerDetailResponse,
    CustomerLicenseSummary
)
from app.schemas.installation import InstallationResponse
from app.services.customer_service import (
    get_all_customers,
    get_customer_by_id,
    get_customer_by_code,
    create_customer,
    update_customer,
    set_customer_status,
    delete_customer,
    get_customer_detail_stats,
    get_customer_installations,
    get_customer_licenses
)
from app.security.dependencies import (
    LicenseApiPrincipal,
    require_authenticated_user,
    require_license_api_principal,
)
from app.models.user import LicenseUser

router = APIRouter(prefix="/api/v1/customers", tags=["Customers"])


@router.get("", response_model=List[CustomerResponse], summary="List All Customers")
def list_customers(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _: LicenseApiPrincipal = Depends(require_license_api_principal)
):
    """Returns list of registered customer organizations."""
    return get_all_customers(db=db, skip=skip, limit=limit)


@router.post("", response_model=CustomerResponse, status_code=status.HTTP_201_CREATED, summary="Create Customer")
def create_new_customer(
    payload: CustomerCreate,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Registers a new customer organization."""
    existing = get_customer_by_code(db=db, code=payload.customer_code)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Kode pelanggan '{payload.customer_code}' sudah terdaftar."
        )
    return create_customer(db=db, data=payload, creator_user_id=current_user.id)


@router.get("/{customer_id}", response_model=CustomerResponse, summary="Get Customer Basic Info")
def get_customer(
    customer_id: UUID,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user)
):
    """Retrieves specific customer basic data by UUID."""
    customer = get_customer_by_id(db=db, customer_id=customer_id)
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pelanggan tidak ditemukan."
        )
    return customer


@router.get("/{customer_id}/detail", response_model=CustomerDetailResponse, summary="Get Customer Complete Detail with Stats")
def get_customer_detail(
    customer_id: UUID,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user)
):
    """Retrieves full customer profile along with linked installations and licenses count."""
    detail = get_customer_detail_stats(db=db, customer_id=customer_id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pelanggan tidak ditemukan."
        )
    return detail


@router.get("/{customer_id}/installations", response_model=List[InstallationResponse], summary="List Customer Installations")
def list_customer_installations(
    customer_id: UUID,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user)
):
    """Returns all installations belonging to a customer."""
    customer = get_customer_by_id(db=db, customer_id=customer_id)
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pelanggan tidak ditemukan."
        )
    return get_customer_installations(db=db, customer_id=customer_id)


@router.get("/{customer_id}/licenses", response_model=List[CustomerLicenseSummary], summary="List Customer Licenses")
def list_customer_licenses(
    customer_id: UUID,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user)
):
    """Returns all commercial licenses issued for a customer."""
    customer = get_customer_by_id(db=db, customer_id=customer_id)
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pelanggan tidak ditemukan."
        )
    return get_customer_licenses(db=db, customer_id=customer_id)


@router.put("/{customer_id}", response_model=CustomerResponse, summary="Update Customer Info")
def update_customer_info(
    customer_id: UUID,
    payload: CustomerUpdate,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Modifies customer organization details."""
    updated = update_customer(db=db, customer_id=customer_id, data=payload, user_id=current_user.id)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pelanggan tidak ditemukan."
        )
    return updated


@router.patch("/{customer_id}/status", response_model=CustomerResponse, summary="Activate or Suspend Customer")
def change_customer_status(
    customer_id: UUID,
    payload: CustomerStatusUpdate,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Changes customer status between ACTIVE, SUSPENDED, and TERMINATED."""
    updated = set_customer_status(
        db=db,
        customer_id=customer_id,
        new_status=payload.status,
        reason=payload.reason,
        user_id=current_user.id
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pelanggan tidak ditemukan."
        )
    return updated


@router.delete("/{customer_id}", summary="Permanently Delete Customer and All Related Data")
def remove_customer(
    customer_id: UUID,
    confirmation: str = Body(..., embed=True),
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Permanently deletes a customer after exact organization-name confirmation."""
    customer = get_customer_by_id(db=db, customer_id=customer_id)
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pelanggan tidak ditemukan.")
    if confirmation.strip() != customer.organization_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Konfirmasi nama organisasi tidak cocok. Penghapusan dibatalkan.")
    success, message = delete_customer(db=db, customer_id=customer_id, user_id=current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    return {"message": message, "customer_id": str(customer_id)}
