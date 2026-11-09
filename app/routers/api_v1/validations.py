"""Periodic license validation endpoints called by SIMPATI instances."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.schemas.license import LicenseValidationRequest
from app.services.validation_service import validate_installation_license

router = APIRouter(prefix="/api/v1/validations", tags=["Validations"])


@router.post("/verify", summary="Verify Installation License Online")
def verify_license(
    payload: LicenseValidationRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Processes validation request sent from a SIMPATI 555 instance.

    Evaluates license validity, grace period, and Restricted Mode rules.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    result = validate_installation_license(
        db=db,
        license_key=payload.license_key,
        installation_code=payload.installation_code,
        request_ip=client_ip
    )
    return result
