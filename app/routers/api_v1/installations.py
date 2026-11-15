"""Installation identity and deployment management API endpoints."""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.installation import Installation
from app.models.user import LicenseUser
from app.schemas.installation import (
    InstallationCreate,
    InstallationUpdate,
    InstallationStatusUpdate,
    InstallationPublicKeyRegister,
    InstallationHeartbeat,
    InstallationResponse,
    InstallationCreateResponse,
    InstallationDetailResponse,
    InstallationEnrollmentConfig,
)
from app.services.installation_service import (
    get_all_installations,
    get_installation_by_id,
    get_installation_by_code,
    create_installation,
    update_installation,
    set_installation_status,
    delete_installation,
    register_public_key,
    record_heartbeat,
    get_installation_detail,
    rotate_installation_credentials,
    generate_enrollment_config,
)
from app.security.dependencies import require_authenticated_user, require_installation_auth

router = APIRouter(prefix="/api/v1/installations", tags=["Installations"])


@router.get("", response_model=List[InstallationResponse], summary="List Installations")
def list_installations(
    customer_id: Optional[UUID] = None,
    status_filter: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user),
):
    """Retrieves registered SIMPATI installations with optional filters."""
    query = db.query(Installation)
    if customer_id:
        query = query.filter(Installation.customer_id == customer_id)
    if status_filter:
        query = query.filter(Installation.status == status_filter)
    return query.order_by(Installation.created_at.desc()).offset(skip).limit(limit).all()


@router.post("", response_model=InstallationCreateResponse, status_code=status.HTTP_201_CREATED, summary="Register Installation")
def register_installation(
    payload: InstallationCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user),
):
    """
    Registers a new SIMPATI server deployment under a customer organization.
    Generates cryptographic API credentials (client_id and client_secret)
    and an installation enrollment token.
    """
    try:
        installation, client_id, client_secret = create_installation(
            db=db,
            data=payload,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    base_url = str(request.base_url).rstrip("/")
    enrollment_token = f"ENROLL:{installation.installation_code}:{client_id}"

    return InstallationCreateResponse(
        id=installation.id,
        customer_id=installation.customer_id,
        installation_code=installation.installation_code,
        name=installation.name,
        server_domain=installation.server_domain,
        server_ip=installation.server_ip,
        environment=installation.environment,
        status=installation.status,
        hardware_signature=installation.hardware_signature,
        public_key_pem=installation.public_key_pem,
        last_heartbeat_at=installation.last_heartbeat_at,
        created_at=installation.created_at,
        updated_at=installation.updated_at,
        client_id=client_id,
        client_secret=client_secret,
        enrollment_token=enrollment_token,
    )


@router.get("/{installation_id}/detail", response_model=InstallationDetailResponse, summary="Get Installation Detail")
@router.get("/{installation_id}", response_model=InstallationDetailResponse, summary="Get Installation by ID")
def get_installation(
    installation_id: UUID,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user),
):
    """Retrieves full installation profile including credentials, activity events, and license links."""
    detail = get_installation_detail(db, installation_id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Instalasi tidak ditemukan.",
        )
    return detail


@router.put("/{installation_id}", response_model=InstallationResponse, summary="Update Installation")
def update_installation_endpoint(
    installation_id: UUID,
    payload: InstallationUpdate,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user),
):
    """Updates attributes of an existing installation (server domain, IP, environment, hardware signature, etc)."""
    try:
        updated = update_installation(
            db=db,
            installation_id=installation_id,
            data=payload,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Instalasi tidak ditemukan.",
        )
    return updated


@router.patch("/{installation_id}/status", response_model=InstallationResponse, summary="Set Installation Status")
def set_status_endpoint(
    installation_id: UUID,
    payload: InstallationStatusUpdate,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user),
):
    """Activates, suspends, or revokes an installation instance."""
    try:
        inst = set_installation_status(
            db=db,
            installation_id=installation_id,
            new_status=payload.status,
            reason=payload.reason,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if not inst:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Instalasi tidak ditemukan.",
        )
    return inst


@router.post("/{installation_id}/public-key", response_model=InstallationResponse, summary="Register Public Key")
def register_public_key_endpoint(
    installation_id: UUID,
    payload: InstallationPublicKeyRegister,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user),
):
    """Registers or updates the Ed25519 public key (PEM format) for this installation."""
    try:
        inst = register_public_key(
            db=db,
            installation_id=installation_id,
            public_key_pem=payload.public_key_pem,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if not inst:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Instalasi tidak ditemukan.",
        )
    return inst


@router.post("/{installation_id}/rotate-credentials", summary="Rotate API Credentials")
def rotate_credentials_endpoint(
    installation_id: UUID,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user),
):
    """
    Revokes the current active API credentials and issues a fresh client_id and client_secret.
    The secret is shown only once in this response.
    """
    rotated = rotate_installation_credentials(
        db=db,
        installation_id=installation_id,
        user_id=current_user.id,
    )
    if not rotated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Instalasi tidak ditemukan.",
        )

    new_client_id, new_client_secret = rotated
    return {
        "message": "Kredensial API instalasi berhasil diperbarui.",
        "client_id": new_client_id,
        "client_secret": new_client_secret,
    }


@router.get("/{installation_id}/enrollment", response_model=InstallationEnrollmentConfig, summary="Get Enrollment Config")
def get_enrollment_config_endpoint(
    installation_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    _: LicenseUser = Depends(require_authenticated_user),
):
    """Generates configuration parameters and .env template for SIMPATI 555 client setup."""
    base_url = str(request.base_url).rstrip("/")
    config = generate_enrollment_config(db, installation_id, base_url=base_url)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Instalasi tidak ditemukan.",
        )
    return config


@router.delete("/{installation_id}", summary="Delete Installation")
def delete_installation_endpoint(
    installation_id: UUID,
    db: Session = Depends(get_db),
    current_user: LicenseUser = Depends(require_authenticated_user),
):
    """Safely deletes an installation only if no active licenses are linked to it."""
    success, message = delete_installation(
        db=db,
        installation_id=installation_id,
        user_id=current_user.id,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return {"message": message}


# ---------------------------------------------------------------------------
# Machine-to-Machine Telemetry Endpoint
# ---------------------------------------------------------------------------

@router.post("/heartbeat", summary="Record Installation Heartbeat")
def heartbeat_endpoint(
    payload: InstallationHeartbeat,
    request: Request,
    db: Session = Depends(get_db),
    auth_installation: Installation = Depends(require_installation_auth),
):
    """
    Public telemetry ping endpoint used by remote SIMPATI 555 servers.
    Verifies that the installation code exists and records telemetry metrics.
    """
    if payload.installation_code != auth_installation.installation_code:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Kode instalasi '{payload.installation_code}' tidak cocok dengan identitas kredensial terotentikasi.",
        )

    inst = auth_installation

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    record_heartbeat(
        db=db,
        installation_id=inst.id,
        version=payload.current_version,
        active_users=payload.active_user_count,
        total_members=payload.total_members_recorded,
        summary=payload.status_summary,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    return {
        "status": "ACKNOWLEDGED",
        "installation_code": inst.installation_code,
        "server_status": inst.status,
    }
