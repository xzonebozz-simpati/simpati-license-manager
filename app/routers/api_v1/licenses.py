"""License lifecycle and entitlement management API endpoints."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.license import License
from app.models.user import LicenseUser
from app.schemas.license import (
    LicenseCreate,
    LicenseExtend,
    LicenseValidityUpdate,
    LicenseStatusUpdate,
    LicenseDetailResponse,
    LicenseActivationRequest,
    LicenseActivationResponse,
)
from app.services.license_service import (
    issue_license,
    compute_license_status,
    extend_license,
    update_license_validity,
    update_license_status,
    get_license_detail,
    bind_installation_to_license,
    get_root_public_key,
)
from app.services.validation_service import (
    LicenseAlreadyActivatedError,
    activate_client_license,
)
from app.security.dependencies import (
    LicenseApiPrincipal,
    require_authenticated_user,
    require_license_api_principal,
)
from fastapi import Request

router = APIRouter(prefix="/api/v1/licenses", tags=["Licenses"])


@router.post("/activate", summary="Activate License Client-side", response_model=LicenseActivationResponse)
def activate_license_alias_endpoint(
    payload: LicenseActivationRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Alias endpoint aktivasi lisensi dari sisi klien SIMPATI 555."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    base_url = str(request.base_url).rstrip("/")
    try:
        res = activate_client_license(
            db=db,
            license_key=payload.license_key,
            server_domain=payload.server_domain,
            server_ip=payload.server_ip or client_ip,
            instance_name=payload.instance_name,
            environment=payload.environment,
        )
        res["server_url"] = base_url
        return res
    except LicenseAlreadyActivatedError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Terjadi kesalahan saat mengaktifkan lisensi: {str(e)}",
        )


@router.get("", summary="List Commercial Licenses")
def list_licenses_endpoint(
    customer_id: Optional[UUID] = None,
    package_id: Optional[UUID] = None,
    status_filter: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _: LicenseApiPrincipal = Depends(require_license_api_principal)
):
    """Retrieves list of issued licenses with live operational status."""
    query = db.query(License)
    if customer_id:
        query = query.filter(License.customer_id == customer_id)
    if package_id:
        query = query.filter(License.package_id == package_id)
    if status_filter:
        query = query.filter(License.status == status_filter)

    licenses = query.order_by(License.created_at.desc()).offset(skip).limit(limit).all()
    results = []
    for lic in licenses:
        linked_inst_codes = [link.installation.installation_code for link in lic.installations if link.installation]
        results.append({
            "id": str(lic.id),
            "license_key": lic.license_key,
            "customer_id": str(lic.customer_id),
            "customer_name": lic.customer.organization_name if lic.customer else "Unknown",
            "package_name": lic.package.package_name if lic.package else "Custom",
            "license_type": lic.license_type,
            "status": lic.status,
            "computed_status": compute_license_status(lic),
            "valid_from": lic.valid_from,
            "valid_until": lic.valid_until,
            "grace_period_days": lic.grace_period_days,
            "max_installations": lic.max_installations,
            "installations_count": len(linked_inst_codes),
            "linked_installations": linked_inst_codes,
            "has_signature": bool(lic.signature),
            "created_at": lic.created_at
        })
    return results


@router.get("/root-public-key", summary="Get License Manager Public Key")
def get_root_public_key_endpoint():
    """Returns the central License Manager Ed25519 public key used for digital verification."""
    return {
        "algorithm": "Ed25519",
        "public_key_pem": get_root_public_key()
    }


@router.post("", status_code=status.HTTP_201_CREATED, summary="Issue Commercial License")
def create_license_endpoint(
    payload: LicenseCreate,
    db: Session = Depends(get_db),
    principal: LicenseApiPrincipal = Depends(require_license_api_principal)
):
    """Issues a new commercial license with immutable snapshot entitlements signed using Ed25519."""
    try:
        lic = issue_license(
            db=db,
            data=payload,
            creator_user_id=principal.user_id,
            service_id=principal.service_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {
        "message": "Lisensi komersial berhasil diterbitkan dan ditandatangani secara digital.",
        "id": str(lic.id),
        "license_id": str(lic.id),
        "license_key": lic.license_key,
        "status": lic.status,
        "valid_from": lic.valid_from,
        "valid_until": lic.valid_until,
        "signature": lic.signature
    }


@router.get("/{license_id}/detail", response_model=LicenseDetailResponse, summary="Get License Detail")
@router.get("/{license_id}", response_model=LicenseDetailResponse, summary="Get License by ID")
def get_license_endpoint(
    license_id: UUID,
    db: Session = Depends(get_db),
    _: LicenseApiPrincipal = Depends(require_license_api_principal)
):
    """Retrieves full license detail, entitlements, linked installations, and digital signature status."""
    detail = get_license_detail(db=db, license_id=license_id)
    if not detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lisensi tidak ditemukan.")
    return detail


@router.post("/{license_id}/extend", summary="Extend/Renew License")
def extend_license_endpoint(
    license_id: UUID,
    payload: LicenseExtend,
    db: Session = Depends(get_db),
    principal: LicenseApiPrincipal = Depends(require_license_api_principal)
):
    """Extends license expiration date and creates a new cryptographic signature."""
    try:
        lic = extend_license(
            db=db,
            license_id=license_id,
            data=payload,
            user_id=principal.user_id,
            service_id=principal.service_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {
        "message": f"Lisensi '{lic.license_key}' berhasil diperpanjang hingga {lic.valid_until.strftime('%d-%m-%Y')}.",
        "license_id": str(lic.id),
        "license_key": lic.license_key,
        "valid_until": lic.valid_until,
        "status": lic.status,
        "signature": lic.signature
    }


@router.patch("/{license_id}/validity", summary="Edit/Correct License Validity Period")
def update_validity_endpoint(
    license_id: UUID,
    payload: LicenseValidityUpdate,
    db: Session = Depends(get_db),
    principal: LicenseApiPrincipal = Depends(require_license_api_principal)
):
    """Mengoreksi periode masa berlaku lisensi (maju/mundur) dan menandatangani ulang snapshot."""
    try:
        lic = update_license_validity(
            db=db,
            license_id=license_id,
            data=payload,
            user_id=principal.user_id,
            service_id=principal.service_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {
        "message": (
            f"Masa berlaku lisensi '{lic.license_key}' berhasil diubah menjadi "
            f"{lic.valid_from.strftime('%d-%m-%Y')} s.d. {lic.valid_until.strftime('%d-%m-%Y')}."
        ),
        "license_id": str(lic.id),
        "license_key": lic.license_key,
        "valid_from": lic.valid_from,
        "valid_until": lic.valid_until,
        "grace_period_days": lic.grace_period_days,
        "status": lic.status,
        "signature": lic.signature
    }


@router.patch("/{license_id}/status", summary="Change License Status")
def update_status_endpoint(
    license_id: UUID,
    payload: LicenseStatusUpdate,
    db: Session = Depends(get_db),
    principal: LicenseApiPrincipal = Depends(require_license_api_principal)
):
    """Suspends, reactivates, or revokes a commercial license with mandatory audit reason."""
    try:
        lic = update_license_status(
            db=db,
            license_id=license_id,
            data=payload,
            user_id=principal.user_id,
            service_id=principal.service_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {
        "message": f"Status lisensi '{lic.license_key}' berhasil diubah menjadi {lic.status}.",
        "license_id": str(lic.id),
        "license_key": lic.license_key,
        "status": lic.status
    }


@router.post("/{license_id}/bind-installation", summary="Bind Installation to License")
def bind_installation_endpoint(
    license_id: UUID,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Binds an installation to a commercial license if quota permits."""
    raw_inst_id = payload.get("installation_id")
    if not raw_inst_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID instalasi wajib disertakan.")

    try:
        inst_uuid = UUID(str(raw_inst_id))
        link = bind_installation_to_license(
            db=db,
            license_id=license_id,
            installation_id=inst_uuid,
            user_id=current_user.id
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {
        "message": "Instalasi berhasil dihubungkan ke lisensi.",
        "license_id": str(link.license_id),
        "installation_id": str(link.installation_id)
    }
