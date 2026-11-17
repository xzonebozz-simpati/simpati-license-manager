"""Periodic license validation endpoints called by SIMPATI instances."""

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.database.session import get_db
from app.models.installation import Installation
from app.models.license import License, LicenseInstallation
from app.models.user import LicenseUser
from app.models.operations import ValidationNonce
from app.schemas.license import LicenseValidationRequest, LicenseActivationRequest, LicenseActivationResponse
from app.security.dependencies import require_installation_auth, require_superadmin
from app.services.validation_service import (
    validate_installation_license,
    activate_client_license,
    LicenseAlreadyActivatedError,
)

router = APIRouter(prefix="/api/v1/validations", tags=["Validations"])


@router.post("/activate", summary="Client-side License Activation", response_model=LicenseActivationResponse)
def activate_license_endpoint(
    payload: LicenseActivationRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Mengaktifkan lisensi SIMPATI 555 langsung menggunakan License Key tanpa manual env credentials."""
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
    except LicenseAlreadyActivatedError as ae:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(ae),
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )


@router.post("/verify", summary="Verify Installation License Online")
def verify_license(
    payload: LicenseValidationRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth_installation: Installation = Depends(require_installation_auth)
):
    """Processes validation request sent from a SIMPATI 555 instance.

    Enforces M2M HTTP Basic Authentication with Client ID and Client Secret.
    Verifies installation identity, license binding, Ed25519 digital signature,
    and Restricted Mode rules.
    """
    if payload.installation_code != auth_installation.installation_code:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Kode instalasi '{payload.installation_code}' tidak cocok dengan identitas kredensial terotentikasi."
        )

    now = datetime.now(timezone.utc)
    if not payload.nonce:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nonce wajib disertakan.")
    if not payload.timestamp or payload.timestamp.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Timestamp bertimezone wajib disertakan untuk validasi lisensi.",
        )
    if abs((now - payload.timestamp.astimezone(timezone.utc)).total_seconds()) > 300:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Timestamp validasi sudah kedaluwarsa.")

    db.query(ValidationNonce).filter(
        ValidationNonce.created_at < now - timedelta(minutes=10)
    ).delete(synchronize_session=False)
    db.add(ValidationNonce(nonce=payload.nonce, installation_id=auth_installation.id))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Nonce validasi telah digunakan.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    result = validate_installation_license(
        db=db,
        license_key=payload.license_key,
        installation_code=payload.installation_code,
        request_ip=client_ip,
        nonce=payload.nonce,
    )
    return result


@router.post("/preview", summary="Dashboard: Preview Validation Result (Superadmin Only)")
def preview_license_validation(
    payload: LicenseValidationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_superadmin)
):
    """Endpoint khusus dashboard superadmin untuk menguji validasi lisensi tanpa M2M credentials.

    Menggunakan session superadmin yang sudah login — tidak perlu input Client ID / Client Secret.
    Hanya untuk keperluan monitoring dan preview dari dashboard, bukan untuk produksi M2M.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    inst_code = payload.installation_code
    license_obj = db.query(License).filter(
        License.license_key == payload.license_key,
        License.deleted_at.is_(None),
    ).first()

    if license_obj:
        # Cek apakah lisensi sudah terikat ke instalasi
        active_links = [l for l in license_obj.installations if l.is_active and l.installation]
        if active_links:
            # Gunakan kode instalasi yang sudah terikat secara valid
            bound_codes = [l.installation.installation_code for l in active_links]
            if not inst_code or inst_code not in bound_codes:
                inst_code = bound_codes[0]
    result = validate_installation_license(
        db=db,
        license_key=payload.license_key,
        installation_code=inst_code,
        request_ip=client_ip
    )
    if "installation_code" not in result:
        result["installation_code"] = inst_code
    return result
