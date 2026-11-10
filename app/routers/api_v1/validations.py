"""Periodic license validation endpoints called by SIMPATI instances."""

from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.installation import Installation
from app.models.user import LicenseUser
from app.schemas.license import LicenseValidationRequest
from app.security.dependencies import require_installation_auth, require_authenticated_user
from app.services.validation_service import validate_installation_license

router = APIRouter(prefix="/api/v1/validations", tags=["Validations"])


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

    client_ip = request.client.host if request.client else "127.0.0.1"
    result = validate_installation_license(
        db=db,
        license_key=payload.license_key,
        installation_code=payload.installation_code,
        request_ip=client_ip
    )
    return result


@router.post("/preview", summary="Dashboard: Preview Validation Result (Superadmin Only)")
def preview_license_validation(
    payload: LicenseValidationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user)
):
    """Endpoint khusus dashboard superadmin untuk menguji validasi lisensi tanpa M2M credentials.

    Menggunakan session superadmin yang sudah login — tidak perlu input Client ID / Client Secret.
    Hanya untuk keperluan monitoring dan preview dari dashboard, bukan untuk produksi M2M.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    result = validate_installation_license(
        db=db,
        license_key=payload.license_key,
        installation_code=payload.installation_code,
        request_ip=client_ip
    )
    return result
