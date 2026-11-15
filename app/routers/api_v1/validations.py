"""Periodic license validation endpoints called by SIMPATI instances."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.installation import Installation
from app.models.license import License, LicenseInstallation
from app.models.user import LicenseUser
from app.schemas.license import LicenseValidationRequest, LicenseActivationRequest, LicenseActivationResponse
from app.security.dependencies import require_installation_auth, require_authenticated_user
from app.services.validation_service import validate_installation_license, activate_client_license

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

    inst_code = payload.installation_code
    license_obj = db.query(License).filter(License.license_key == payload.license_key).first()

    if license_obj:
        # Cek apakah lisensi sudah terikat ke instalasi
        active_links = [l for l in license_obj.installations if l.is_active and l.installation]
        if active_links:
            # Gunakan kode instalasi yang sudah terikat secara valid
            bound_codes = [l.installation.installation_code for l in active_links]
            if not inst_code or inst_code not in bound_codes:
                inst_code = bound_codes[0]
        else:
            # Lisensi belum memiliki ikatan instalasi. Cari instalasi yang relevan untuk diikatkan
            target_inst = None
            if inst_code:
                target_inst = db.query(Installation).filter(Installation.installation_code == inst_code).first()
            if not target_inst and license_obj.customer_id:
                target_inst = db.query(Installation).filter(Installation.customer_id == license_obj.customer_id).first()
            if not target_inst:
                target_inst = db.query(Installation).first()

            if target_inst:
                new_bind = LicenseInstallation(
                    license_id=license_obj.id,
                    installation_id=target_inst.id,
                    is_active=True,
                    activated_at=datetime.now(timezone.utc)
                )
                db.add(new_bind)
                db.commit()
                inst_code = target_inst.installation_code

    result = validate_installation_license(
        db=db,
        license_key=payload.license_key,
        installation_code=inst_code,
        request_ip=client_ip
    )
    if "installation_code" not in result:
        result["installation_code"] = inst_code
    return result
