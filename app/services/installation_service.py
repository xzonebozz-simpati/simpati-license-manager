"""Installation lifecycle and cryptographic identity management service."""

import secrets
import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.installation import Installation, InstallationCredential, InstallationEvent
from app.models.customer import Customer
from app.models.license import License, LicenseInstallation
from app.models.operations import LicenseValidation
from app.schemas.installation import (
    InstallationCreate,
    InstallationUpdate,
    InstallationStatusUpdate,
)
from app.services.audit_service import log_audit_event
from app.security.hashing import hash_password, verify_password


# ---------------------------------------------------------------------------
# ID & Credential Generation
# ---------------------------------------------------------------------------

def generate_installation_code(customer_code: str) -> str:
    """Generates a unique installation code: INST-{CUST_PREFIX}-{RANDOM6}."""
    prefix = customer_code[:6].upper().replace("-", "")
    rand = secrets.token_hex(3).upper()
    return f"INST-{prefix}-{rand}"


def generate_client_credentials() -> Tuple[str, str, str]:
    """
    Generates a (client_id, client_secret_plaintext, client_secret_hash) triple
    for installation API authentication.
    """
    client_id = "CLT-" + secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    secret_hash = hash_password(client_secret)
    return client_id, client_secret, secret_hash


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def get_all_installations(db: Session, skip: int = 0, limit: int = 200) -> List[Installation]:
    """Retrieves all registered installations ordered by newest first."""
    return (
        db.query(Installation)
        .order_by(Installation.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_installation_by_id(db: Session, installation_id: UUID) -> Optional[Installation]:
    """Finds an installation by primary key UUID."""
    return db.query(Installation).filter(Installation.id == installation_id).first()


def get_installation_by_code(db: Session, code: str) -> Optional[Installation]:
    """Finds an installation by its unique installation_code."""
    return db.query(Installation).filter(Installation.installation_code == code).first()


def create_installation(
    db: Session,
    data: InstallationCreate,
    user_id: Optional[UUID] = None,
) -> Tuple[Installation, str, str]:
    """
    Registers a new SIMPATI server installation under a customer.

    Automatically:
    - Generates a unique installation_code if not provided.
    - Creates initial API credentials (client_id / client_secret).
    - Logs an INSTALLATION_REGISTERED audit event.

    Returns: (Installation ORM object, plaintext client_id, plaintext client_secret for one-time display)
    """
    from app.models.customer import Customer

    customer = db.query(Customer).filter(Customer.id == data.customer_id).first()
    if not customer:
        raise ValueError(f"Pelanggan dengan ID {data.customer_id} tidak ditemukan.")

    # Auto-generate installation code if not provided
    code = data.installation_code.strip() if data.installation_code else None
    if not code:
        code = generate_installation_code(customer.customer_code)

    # Ensure uniqueness
    if db.query(Installation).filter(Installation.installation_code == code).first():
        raise ValueError(f"Kode instalasi '{code}' sudah terdaftar. Gunakan kode lain.")

    installation = Installation(
        customer_id=data.customer_id,
        installation_code=code,
        name=data.name.strip(),
        server_domain=data.server_domain.strip() if data.server_domain else None,
        server_ip=data.server_ip.strip() if data.server_ip else None,
        environment=data.environment or "PRODUCTION",
        public_key_pem=data.public_key_pem.strip() if data.public_key_pem else None,
        hardware_signature=data.hardware_signature.strip() if data.hardware_signature else None,
        status="ACTIVE",
    )
    db.add(installation)
    db.flush()  # get installation.id before credential insert

    # Create initial API credentials
    client_id, client_secret_plain, secret_hash = generate_client_credentials()
    credential = InstallationCredential(
        installation_id=installation.id,
        client_id=client_id,
        client_secret_hash=secret_hash,
        is_active=True,
    )
    db.add(credential)

    # Record initial event
    event = InstallationEvent(
        installation_id=installation.id,
        event_type="REGISTERED",
        payload=f"Instalasi '{installation.name}' didaftarkan ke sistem lisensi pusat.",
    )
    db.add(event)

    db.commit()
    db.refresh(installation)

    log_audit_event(
        db=db,
        action_category="INSTALLATION",
        action_name="INSTALLATION_REGISTERED",
        user_id=user_id,
        target_resource=f"installation:{code}",
        details={
            "name": installation.name,
            "customer": customer.organization_name,
            "environment": installation.environment,
            "client_id": client_id,
        },
    )

    return installation, client_id, client_secret_plain


def update_installation(
    db: Session,
    installation_id: UUID,
    data: InstallationUpdate,
    user_id: Optional[UUID] = None,
) -> Optional[Installation]:
    """Updates mutable attributes of an installation."""
    inst = get_installation_by_id(db, installation_id)
    if not inst:
        return None

    changes: Dict[str, Any] = {}
    if "customer_id" in data.model_fields_set:
        if data.customer_id is not None:
            customer = db.query(Customer).filter(Customer.id == data.customer_id).first()
            if not customer:
                raise ValueError("Pelanggan tidak ditemukan.")
            if customer.status != "ACTIVE":
                raise ValueError("Pelanggan tidak aktif dan tidak dapat dihubungkan.")
        if data.customer_id != inst.customer_id:
            changes["customer_id"] = {
                "from": str(inst.customer_id) if inst.customer_id else None,
                "to": str(data.customer_id) if data.customer_id else None,
            }
            inst.customer_id = data.customer_id
    if data.name is not None and data.name.strip() != inst.name:
        changes["name"] = {"from": inst.name, "to": data.name.strip()}
        inst.name = data.name.strip()
    if data.server_domain is not None:
        inst.server_domain = data.server_domain.strip() if data.server_domain else None
    if data.server_ip is not None:
        inst.server_ip = data.server_ip.strip() if data.server_ip else None
    if data.environment is not None and data.environment != inst.environment:
        changes["environment"] = {"from": inst.environment, "to": data.environment}
        inst.environment = data.environment
    if data.public_key_pem is not None:
        inst.public_key_pem = data.public_key_pem.strip() if data.public_key_pem else None
        changes["public_key_updated"] = True
    if data.hardware_signature is not None:
        inst.hardware_signature = data.hardware_signature.strip() if data.hardware_signature else None

    db.commit()
    db.refresh(inst)

    if changes:
        log_audit_event(
            db=db,
            action_category="INSTALLATION",
            action_name="INSTALLATION_UPDATED",
            user_id=user_id,
            target_resource=f"installation:{inst.installation_code}",
            details=changes,
        )
    return inst


def set_installation_status(
    db: Session,
    installation_id: UUID,
    new_status: str,
    reason: Optional[str] = None,
    user_id: Optional[UUID] = None,
) -> Optional[Installation]:
    """Changes the operational status of an installation (ACTIVE / SUSPENDED / REVOKED)."""
    inst = get_installation_by_id(db, installation_id)
    if not inst:
        return None

    allowed = {"ACTIVE", "SUSPENDED", "REVOKED"}
    if new_status not in allowed:
        raise ValueError(f"Status tidak valid: {new_status}. Pilih: {allowed}")

    old_status = inst.status
    inst.status = new_status

    event = InstallationEvent(
        installation_id=installation_id,
        event_type="STATUS_CHANGED",
        payload=f"Status diubah dari {old_status} ke {new_status}. Alasan: {reason or 'Manual'}",
    )
    db.add(event)
    db.commit()
    db.refresh(inst)

    log_audit_event(
        db=db,
        action_category="INSTALLATION",
        action_name="INSTALLATION_STATUS_CHANGED",
        user_id=user_id,
        target_resource=f"installation:{inst.installation_code}",
        details={"from": old_status, "to": new_status, "reason": reason or "Perubahan status manual"},
    )
    return inst


def delete_installation(
    db: Session,
    installation_id: UUID,
    user_id: Optional[UUID] = None,
) -> Tuple[bool, str]:
    """
    Safely deletes an installation only if it has no active linked licenses.
    Events and credentials are cascade-deleted automatically.
    """
    inst = get_installation_by_id(db, installation_id)
    if not inst:
        return False, "Instalasi tidak ditemukan."

    # Guard: active license links
    active_links = (
        db.query(LicenseInstallation)
        .filter(LicenseInstallation.installation_id == installation_id)
        .count()
    )
    if active_links > 0:
        return False, (
            f"Instalasi '{inst.name}' tidak dapat dihapus karena masih terhubung dengan "
            f"{active_links} lisensi komersial. Cabut seluruh kaitannya terlebih dahulu."
        )

    code = inst.installation_code
    name = inst.name

    db.delete(inst)
    db.commit()

    log_audit_event(
        db=db,
        action_category="INSTALLATION",
        action_name="INSTALLATION_DELETED",
        user_id=user_id,
        target_resource=f"installation:{code}",
        details={"deleted_installation": name},
    )
    return True, f"Instalasi '{name}' ({code}) berhasil dihapus secara aman."


# ---------------------------------------------------------------------------
# Public Key Registration
# ---------------------------------------------------------------------------

def register_public_key(
    db: Session,
    installation_id: UUID,
    public_key_pem: str,
    user_id: Optional[UUID] = None,
) -> Optional[Installation]:
    """Registers or replaces the Ed25519 public key of an installation."""
    inst = get_installation_by_id(db, installation_id)
    if not inst:
        return None

    pem_stripped = public_key_pem.strip()
    if not (pem_stripped.startswith("-----BEGIN") and "-----END" in pem_stripped):
        raise ValueError("Format public key tidak valid. Gunakan format PEM standar (-----BEGIN ... -----END).")

    inst.public_key_pem = pem_stripped
    event = InstallationEvent(
        installation_id=installation_id,
        event_type="PUBLIC_KEY_REGISTERED",
        payload=f"Public key PEM baru didaftarkan. Fingerprint: {_pem_fingerprint(pem_stripped)}",
    )
    db.add(event)
    db.commit()
    db.refresh(inst)

    log_audit_event(
        db=db,
        action_category="INSTALLATION",
        action_name="PUBLIC_KEY_REGISTERED",
        user_id=user_id,
        target_resource=f"installation:{inst.installation_code}",
        details={"key_fingerprint": _pem_fingerprint(pem_stripped)},
    )
    return inst


def _pem_fingerprint(pem: str) -> str:
    """Returns SHA-256 fingerprint of PEM public key (formatted hex)."""
    digest = hashlib.sha256(pem.encode("utf-8")).hexdigest()
    # Format as 12-char upper chunk
    return digest[:16].upper()


# ---------------------------------------------------------------------------
# Installation Authentication & Heartbeat
# ---------------------------------------------------------------------------

def authenticate_installation(
    db: Session,
    client_id: str,
    client_secret: str,
) -> Optional[Installation]:
    """
    Verifies installation credentials (client_id + client_secret).
    Returns the associated Installation if valid and ACTIVE, else None.
    """
    credential = (
        db.query(InstallationCredential)
        .filter(
            InstallationCredential.client_id == client_id,
            InstallationCredential.is_active == True,
        )
        .first()
    )
    if not credential:
        return None

    if not verify_password(client_secret, credential.client_secret_hash):
        return None

    installation = get_installation_by_id(db, credential.installation_id)
    if not installation or installation.status != "ACTIVE":
        return None

    return installation


def record_heartbeat(
    db: Session,
    installation_id: UUID,
    version: str = "555.2.0",
    active_users: int = 0,
    total_members: int = 0,
    summary: str = "HEALTHY",
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Optional[Installation]:
    """Updates last heartbeat timestamp and logs the telemetry event."""
    inst = get_installation_by_id(db, installation_id)
    if not inst:
        return None

    inst.last_heartbeat_at = datetime.now(timezone.utc)
    if ip_address:
        inst.server_ip = ip_address

    event = InstallationEvent(
        installation_id=installation_id,
        event_type="HEARTBEAT",
        payload=f"v{version} | Users aktif: {active_users} | Data jemaat: {total_members} | Status: {summary}",
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(event)
    db.commit()
    db.refresh(inst)
    return inst


# ---------------------------------------------------------------------------
# Detail & Related Data
# ---------------------------------------------------------------------------

def get_installation_detail(db: Session, installation_id: UUID) -> Optional[Dict[str, Any]]:
    """Assembles full installation detail including credentials, events, and license links."""
    inst = get_installation_by_id(db, installation_id)
    if not inst:
        return None

    credentials = (
        db.query(InstallationCredential)
        .filter(InstallationCredential.installation_id == installation_id)
        .order_by(InstallationCredential.created_at.desc())
        .all()
    )
    events = (
        db.query(InstallationEvent)
        .filter(InstallationEvent.installation_id == installation_id)
        .order_by(InstallationEvent.recorded_at.desc())
        .limit(50)
        .all()
    )
    license_links = (
        db.query(LicenseInstallation)
        .filter(LicenseInstallation.installation_id == installation_id)
        .all()
    )
    validations = (
        db.query(LicenseValidation)
        .filter(LicenseValidation.installation_id == installation_id)
        .order_by(LicenseValidation.validated_at.desc())
        .limit(20)
        .all()
    )

    fingerprint = None
    if inst.public_key_pem:
        fingerprint = _pem_fingerprint(inst.public_key_pem)

    return {
        "id": inst.id,
        "installation_code": inst.installation_code,
        "name": inst.name,
        "customer_id": inst.customer_id,
        "customer_name": inst.customer.organization_name if inst.customer else None,
        "customer_code": inst.customer.customer_code if inst.customer else None,
        "customer": inst.customer,
        "server_domain": inst.server_domain,
        "server_ip": inst.server_ip,
        "environment": inst.environment,
        "status": inst.status,
        "public_key_pem": inst.public_key_pem,
        "public_key_fingerprint": fingerprint,
        "hardware_signature": inst.hardware_signature,
        "last_heartbeat_at": inst.last_heartbeat_at,
        "created_at": inst.created_at,
        "updated_at": inst.updated_at,
        "credentials": credentials,
        "events": events,
        "license_links": license_links,
        "validations": validations,
        "total_events": len(events),
        "total_validations": len(validations),
        "total_license_links": len(license_links),
        "has_public_key": bool(inst.public_key_pem),
    }


def rotate_installation_credentials(
    db: Session,
    installation_id: UUID,
    user_id: Optional[UUID] = None,
) -> Optional[Tuple[str, str]]:
    """
    Rotates API credentials: revokes current active credentials and creates a new one.

    Returns: (new_client_id, new_client_secret_plaintext) or None if not found.
    """
    inst = get_installation_by_id(db, installation_id)
    if not inst:
        return None

    now = datetime.now(timezone.utc)
    active_creds = (
        db.query(InstallationCredential)
        .filter(
            InstallationCredential.installation_id == installation_id,
            InstallationCredential.is_active == True,
        )
        .all()
    )
    for cred in active_creds:
        cred.is_active = False
        cred.revoked_at = now

    client_id, client_secret_plain, secret_hash = generate_client_credentials()
    new_cred = InstallationCredential(
        installation_id=installation_id,
        client_id=client_id,
        client_secret_hash=secret_hash,
        is_active=True,
    )
    db.add(new_cred)

    event = InstallationEvent(
        installation_id=installation_id,
        event_type="CREDENTIALS_ROTATED",
        payload=f"Kredensial API dirotasi. Client ID baru: {client_id}",
    )
    db.add(event)
    db.commit()

    log_audit_event(
        db=db,
        action_category="INSTALLATION",
        action_name="CREDENTIALS_ROTATED",
        user_id=user_id,
        target_resource=f"installation:{inst.installation_code}",
        details={"new_client_id": client_id, "revoked_count": len(active_creds)},
    )

    return client_id, client_secret_plain


def generate_enrollment_config(
    db: Session,
    installation_id: UUID,
    base_url: str = "http://localhost:8000",
) -> Optional[Dict[str, Any]]:
    """
    Builds the configuration parameters required for a SIMPATI 555 client
    to connect and register with the License Manager.
    """
    inst = get_installation_by_id(db, installation_id)
    if not inst:
        return None

    active_cred = (
        db.query(InstallationCredential)
        .filter(
            InstallationCredential.installation_id == installation_id,
            InstallationCredential.is_active == True,
        )
        .order_by(InstallationCredential.created_at.desc())
        .first()
    )

    client_id = active_cred.client_id if active_cred else "BELUM_DISET"
    cust_code = inst.customer.customer_code if inst.customer else "UNKNOWN"
    cust_name = inst.customer.organization_name if inst.customer else "UNKNOWN"

    env_template = (
        f"# =========================================================\n"
        f"# SIMPATI 555 LICENSE MANAGER INTEGRATION CONFIG\n"
        f"# Target Instance: {inst.name} ({inst.installation_code})\n"
        f"# Customer: {cust_name} ({cust_code})\n"
        f"# =========================================================\n"
        f"SIMPATI_LICENSE_SERVER_URL={base_url}\n"
        f"SIMPATI_INSTALLATION_CODE={inst.installation_code}\n"
        f"SIMPATI_CLIENT_ID={client_id}\n"
        f"# Masukkan CLIENT_SECRET yang diperoleh saat pembuatan/rotasi kredensial\n"
        f"SIMPATI_CLIENT_SECRET=\n"
        f"SIMPATI_ENVIRONMENT={inst.environment}\n"
    )

    return {
        "license_server_url": base_url,
        "installation_code": inst.installation_code,
        "client_id": client_id,
        "environment": inst.environment,
        "customer_code": cust_code,
        "customer_name": cust_name,
        "recommended_env": env_template,
    }
