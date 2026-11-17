"""Commercial license lifecycle, entitlement snapshot, and cryptographic signing service."""

import json
import secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.license import License, LicenseModule, LicenseCapacity, LicenseInstallation
from app.models.region import LicenseOrganizationalLevel
from app.models.operations import LicenseHistory
from app.models.catalog import LicensePackage
from app.models.customer import Customer
from app.models.installation import Installation
from app.models.security import RevocationRecord
from app.schemas.license import LicenseCreate, LicenseExtend, LicenseStatusUpdate, LicenseValidityUpdate
from app.services.audit_service import log_audit_event
from app.security.crypto import sign_payload, verify_signature, generate_ed25519_keypair


settings = get_settings()


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime is timezone-aware in UTC (normalizes SQLite naive datetimes)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generate_license_key() -> str:
    """Generates a license key with 128 bits of cryptographic entropy."""
    current_year = datetime.now().year
    part1 = secrets.token_hex(8).upper()
    part2 = secrets.token_hex(8).upper()
    return f"SMP-LIC-{current_year}-{part1}-{part2}"


# ---------------------------------------------------------------------------
# Cryptographic Key Helpers
# ---------------------------------------------------------------------------

def get_or_load_root_signing_keys() -> Tuple[str, str]:
    """
    Loads root Ed25519 keys prioritizing environment variables (12-factor cloud deployment),
    falling back to file vault, or generating a fresh keypair for development.
    Returns: (private_key_pem, public_key_pem)
    """
    # 1. Environment Variable / Cloud Secret Storage (Recommended for Hostless)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    def normalize_pem(value: str) -> str:
        value = value.strip()
        return value.replace("\\n", "\n") if "\\n" in value and "\n" not in value else value

    def validate_key_pair(private_pem: str, public_pem: Optional[str] = None) -> Tuple[str, str]:
        private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Root signing key must be Ed25519.")
        derived_public = private_key.public_key()
        derived_pem = derived_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8").strip()
        if public_pem:
            supplied_public = serialization.load_pem_public_key(public_pem.encode("utf-8"))
            if not isinstance(supplied_public, ed25519.Ed25519PublicKey):
                raise ValueError("Root public key must be Ed25519.")
            if supplied_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ) != derived_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ):
                raise ValueError("Root Ed25519 private and public keys do not match.")
            return private_pem, public_pem
        return private_pem, derived_pem

    if settings.ED25519_PRIVATE_KEY_PEM:
        return validate_key_pair(
            normalize_pem(settings.ED25519_PRIVATE_KEY_PEM),
            normalize_pem(settings.ED25519_PUBLIC_KEY_PEM) if settings.ED25519_PUBLIC_KEY_PEM else None,
        )

    # 2. Local File Vault Storage
    vault_path = Path(settings.SIGNING_KEY_VAULT_PATH)
    pub_path = vault_path.with_suffix(".pub")

    if vault_path.exists() and pub_path.exists():
        priv_pem = vault_path.read_text(encoding="utf-8").strip()
        pub_pem = pub_path.read_text(encoding="utf-8").strip()
        return validate_key_pair(priv_pem, pub_pem)

    if settings.is_production:
        raise RuntimeError("Ed25519 signing keys must be configured before production startup.")

    # 3. Fallback: Generate and persist new keys if absent (development only)
    vault_path.parent.mkdir(parents=True, exist_ok=True)

    priv_pem, pub_pem = generate_ed25519_keypair()
    vault_path.write_text(priv_pem, encoding="utf-8")
    pub_path.write_text(pub_pem, encoding="utf-8")
    return priv_pem, pub_pem


def get_root_public_key() -> str:
    """Returns the root Ed25519 public key PEM used for license validation."""
    _, pub_pem = get_or_load_root_signing_keys()
    return pub_pem


# ---------------------------------------------------------------------------
# Status Computation
# ---------------------------------------------------------------------------

def compute_license_status(license_obj: License) -> str:
    """Determines real-time operational status based on dates, grace period, and overrides."""
    # Status override administratif selalu menang. TERMINATED/EXPIRED sebelumnya tidak
    # ditangani sehingga lisensi yang sudah dihentikan bisa terhitung ACTIVE menurut tanggal.
    if license_obj.status in ["REVOKED", "SUSPENDED", "DRAFT", "TERMINATED", "EXPIRED"]:
        return license_obj.status

    now = datetime.now(timezone.utc)
    valid_from = ensure_utc(license_obj.valid_from)
    valid_until = ensure_utc(license_obj.valid_until)

    if valid_from and now < valid_from:
        return "PENDING_ACTIVATION"

    # Tanpa tanggal berakhir yang sah, jangan pernah dianggap aktif.
    if not valid_until:
        return "RESTRICTED"

    if now <= valid_until:
        return "ACTIVE"

    # Expired, check grace period
    grace_days = max(0, int(license_obj.grace_period_days or 0))
    if now <= valid_until + timedelta(days=grace_days):
        return "GRACE_PERIOD"

    # Beyond grace period
    return "RESTRICTED"


def has_license_revocation(db: Session, license_id: UUID) -> bool:
    """Checks the permanent revocation ledger independently of the mutable status field."""
    return db.query(RevocationRecord).filter(
        RevocationRecord.entity_type == "LICENSE",
        RevocationRecord.entity_id == license_id,
    ).first() is not None


# ---------------------------------------------------------------------------
# License Issuance & Snapshot Signing
# ---------------------------------------------------------------------------

def issue_license(
    db: Session,
    data: LicenseCreate,
    creator_user_id: Optional[UUID] = None
) -> License:
    """
    Issues a new commercial license with immutable snapshot entitlements
    signed using Ed25519 digital signature.
    """
    customer = db.query(Customer).filter(Customer.id == data.customer_id).first()
    if not customer:
        raise ValueError(f"Pelanggan dengan ID {data.customer_id} tidak ditemukan.")
    if customer.status != "ACTIVE":
        raise ValueError("Lisensi tidak dapat diterbitkan untuk pelanggan yang tidak aktif.")

    package = db.query(LicensePackage).filter(LicensePackage.id == data.package_id).first()
    if not package:
        raise ValueError(f"Paket lisensi dengan ID {data.package_id} tidak ditemukan.")
    if not package.is_active:
        raise ValueError("Lisensi tidak dapat diterbitkan menggunakan paket yang tidak aktif.")

    # Validate installation if supplied
    installation = None
    if data.installation_id:
        installation = db.query(Installation).filter(
            Installation.id == data.installation_id,
            Installation.customer_id == data.customer_id
        ).first()
        if not installation:
            raise ValueError(f"Instalasi ID {data.installation_id} tidak ditemukan atau bukan milik pelanggan ini.")

    license_key = generate_license_key()
    valid_from_utc = ensure_utc(data.valid_from)
    valid_until_utc = ensure_utc(data.valid_until)

    if valid_until_utc <= valid_from_utc:
        raise ValueError("Tanggal kedaluwarsa (valid_until) harus setelah tanggal mulai berlaku (valid_from).")

    # Build canonical snapshot payload
    snapshot_payload: Dict[str, Any] = {
        "license_key": license_key,
        "customer_id": str(customer.id),
        "customer_code": customer.customer_code,
        "customer_name": customer.organization_name,
        "package_id": str(package.id),
        "package_code": package.package_code,
        "package_name": package.package_name,
        "license_type": data.license_type,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "valid_from": valid_from_utc.isoformat(),
        "valid_until": valid_until_utc.isoformat(),
        "grace_period_days": data.grace_period_days,
        "max_installations": data.max_installations,
        "modules": sorted(list(set(data.modules))),
        "levels": sorted(list(set(data.levels))),
        "capacity": data.capacity.model_dump(),
        "linked_installation": installation.installation_code if installation else None
    }
    canonical_json = json.dumps(snapshot_payload, sort_keys=True, separators=(',', ':'))

    # Digital signature with Ed25519
    priv_pem, _ = get_or_load_root_signing_keys()
    signature_b64 = sign_payload(priv_pem, canonical_json.encode("utf-8"))

    new_license = License(
        license_key=license_key,
        customer_id=data.customer_id,
        package_id=data.package_id,
        license_type=data.license_type,
        status="ACTIVE",
        valid_from=valid_from_utc,
        valid_until=valid_until_utc,
        grace_period_days=data.grace_period_days,
        max_installations=data.max_installations,
        snapshot_entitlements=canonical_json,
        signature=signature_b64,
        notes=data.notes
    )
    db.add(new_license)
    db.flush()

    # Link installation if chosen
    if installation:
        lic_inst = LicenseInstallation(
            license_id=new_license.id,
            installation_id=installation.id,
            is_active=True
        )
        db.add(lic_inst)

    # Attach modules
    for mod in data.modules:
        lic_mod = LicenseModule(
            license_id=new_license.id,
            module_code=mod.strip(),
            is_enabled=True
        )
        db.add(lic_mod)

    # Attach organizational levels
    for lvl in data.levels:
        lic_lvl = LicenseOrganizationalLevel(
            license_id=new_license.id,
            level_name=lvl.strip(),
            is_allowed=True,
            max_units=1
        )
        db.add(lic_lvl)

    # Attach capacity
    lic_cap = LicenseCapacity(
        license_id=new_license.id,
        max_members=data.capacity.max_members,
        max_accounts=data.capacity.max_accounts,
        max_concurrent_users=data.capacity.max_concurrent_users,
        max_storage_mb=data.capacity.max_storage_mb,
        max_gps_points_per_month=data.capacity.max_gps_points_per_month
    )
    db.add(lic_cap)

    # Record history
    history = LicenseHistory(
        license_id=new_license.id,
        action="ISSUED",
        new_values=canonical_json,
        performed_by_user_id=creator_user_id,
        remarks=f"Penerbitan lisensi komersial dengan tanda tangan digital Ed25519. Terikat instalasi: {installation.name if installation else 'Belum diikat'}."
    )
    db.add(history)
    db.commit()
    db.refresh(new_license)

    log_audit_event(
        db=db,
        action_category="LICENSE",
        action_name="LICENSE_ISSUED",
        user_id=creator_user_id,
        target_resource=f"license:{new_license.id}",
        details={
            "customer": customer.organization_name,
            "package": package.package_name,
            "status": new_license.status,
            "signature_length": len(signature_b64)
        }
    )
    return new_license


# ---------------------------------------------------------------------------
# License Extension (Perpanjangan)
# ---------------------------------------------------------------------------

def extend_license(
    db: Session,
    license_id: UUID,
    data: LicenseExtend,
    user_id: Optional[UUID] = None
) -> License:
    """Extends the expiration date of a license and signs the updated snapshot."""
    license_obj = db.query(License).filter(License.id == license_id, License.deleted_at.is_(None)).first()
    if not license_obj:
        raise ValueError("Lisensi tidak ditemukan.")
    if has_license_revocation(db, license_obj.id):
        raise ValueError("Lisensi yang telah dicabut tidak dapat diperpanjang.")
    if license_obj.status in ("REVOKED", "TERMINATED"):
        raise ValueError(f"Lisensi berstatus {license_obj.status} dan tidak dapat diperpanjang.")

    old_until = ensure_utc(license_obj.valid_until)
    new_until = ensure_utc(data.valid_until)

    if new_until <= old_until:
        raise ValueError(
            f"Tanggal perpanjangan ({new_until.strftime('%d-%m-%Y')}) harus lebih besar dari tanggal kedaluwarsa saat ini ({old_until.strftime('%d-%m-%Y')})."
        )

    # Update expiration
    license_obj.valid_until = new_until
    # Perpanjangan harus memulihkan status yang diturunkan karena masa berlaku habis.
    # compute_license_status() memprioritaskan status administratif (EXPIRED/RESTRICTED/
    # PENDING_ACTIVATION), sehingga tanpa reset ini lisensi yang sudah diperpanjang tetap
    # dianggap tidak aktif oleh CORE. SUSPENDED/REVOKED/TERMINATED adalah keputusan
    # administratif dan hanya dipulihkan lewat perubahan status eksplisit.
    if license_obj.status in ("EXPIRED", "RESTRICTED", "PENDING_ACTIVATION"):
        license_obj.status = "ACTIVE"

    # Update snapshot
    snapshot_data: Dict[str, Any] = {}
    if license_obj.snapshot_entitlements:
        try:
            snapshot_data = json.loads(license_obj.snapshot_entitlements)
        except Exception:
            pass

    snapshot_data["valid_until"] = new_until.isoformat()
    snapshot_data["last_extended_at"] = datetime.now(timezone.utc).isoformat()
    snapshot_data["extension_reason"] = data.reason or "Perpanjangan lisensi komersial"

    canonical_json = json.dumps(snapshot_data, sort_keys=True, separators=(',', ':'))

    # Re-sign with Ed25519
    priv_pem, _ = get_or_load_root_signing_keys()
    signature_b64 = sign_payload(priv_pem, canonical_json.encode("utf-8"))

    license_obj.snapshot_entitlements = canonical_json
    license_obj.signature = signature_b64

    # Record history
    history = LicenseHistory(
        license_id=license_obj.id,
        action="EXTENDED",
        old_values=old_until.isoformat(),
        new_values=new_until.isoformat(),
        performed_by_user_id=user_id,
        remarks=f"Perpanjangan masa berlaku lisensi sampai {new_until.strftime('%d-%m-%Y')}. Alasan: {data.reason or 'Perpanjangan reguler'}."
    )
    db.add(history)
    db.commit()
    db.refresh(license_obj)

    log_audit_event(
        db=db,
        action_category="LICENSE",
        action_name="LICENSE_EXTENDED",
        user_id=user_id,
        target_resource=f"license:{license_obj.id}",
        details={
            "old_until": old_until.isoformat(),
            "new_until": new_until.isoformat(),
            "reason": data.reason
        }
    )
    return license_obj


# ---------------------------------------------------------------------------
# License Validity Correction (Edit jangka waktu / koreksi salah input)
# ---------------------------------------------------------------------------

def update_license_validity(
    db: Session,
    license_id: UUID,
    data: LicenseValidityUpdate,
    user_id: Optional[UUID] = None
) -> License:
    """
    Mengoreksi periode masa berlaku (valid_from, valid_until, opsional grace period)
    pada lisensi yang sudah diterbitkan. Berbeda dengan extend_license(), tanggal baru
    boleh lebih awal maupun lebih akhir dari tanggal lama. Snapshot ditandatangani ulang.
    """
    license_obj = db.query(License).filter(License.id == license_id, License.deleted_at.is_(None)).first()
    if not license_obj:
        raise ValueError("Lisensi tidak ditemukan.")

    if has_license_revocation(db, license_obj.id):
        raise ValueError("Lisensi yang telah dicabut secara permanen tidak dapat diubah masa berlakunya.")
    if license_obj.status in ("REVOKED", "TERMINATED"):
        raise ValueError(
            f"Lisensi berstatus {license_obj.status} dan tidak dapat diubah masa berlakunya."
        )

    old_from = ensure_utc(license_obj.valid_from)
    old_until = ensure_utc(license_obj.valid_until)
    old_grace = license_obj.grace_period_days
    new_from = ensure_utc(data.valid_from)
    new_until = ensure_utc(data.valid_until)
    new_grace = data.grace_period_days if data.grace_period_days is not None else old_grace

    if new_until <= new_from:
        raise ValueError("Tanggal kedaluwarsa harus setelah tanggal mulai berlaku.")

    if new_from == old_from and new_until == old_until and new_grace == old_grace:
        raise ValueError("Tidak ada perubahan: periode yang dimasukkan sama dengan periode saat ini.")

    license_obj.valid_from = new_from
    license_obj.valid_until = new_until
    license_obj.grace_period_days = new_grace

    # Status EXPIRED/RESTRICTED/PENDING_ACTIVATION diturunkan dari tanggal lama. Jika periode
    # baru membuat lisensi kembali berlaku (atau belum mulai), pulihkan ke ACTIVE agar
    # compute_license_status() menghitung ulang dari tanggal. SUSPENDED/REVOKED tetap
    # keputusan administratif dan tidak disentuh di sini.
    now = datetime.now(timezone.utc)
    if license_obj.status in ("EXPIRED", "RESTRICTED", "PENDING_ACTIVATION", "DRAFT"):
        if now <= new_until + timedelta(days=max(0, int(new_grace or 0))):
            license_obj.status = "ACTIVE"
    elif license_obj.status == "ACTIVE" and now > new_until + timedelta(days=max(0, int(new_grace or 0))):
        # Periode dipersingkat sampai sudah lewat: biarkan ACTIVE, status real-time
        # (computed_status) otomatis menjadi RESTRICTED.
        pass

    # Update snapshot & tanda tangan ulang
    snapshot_data: Dict[str, Any] = {}
    if license_obj.snapshot_entitlements:
        try:
            snapshot_data = json.loads(license_obj.snapshot_entitlements)
        except Exception:
            pass

    snapshot_data["valid_from"] = new_from.isoformat()
    snapshot_data["valid_until"] = new_until.isoformat()
    snapshot_data["grace_period_days"] = new_grace
    snapshot_data["last_validity_edit_at"] = now.isoformat()
    snapshot_data["validity_edit_reason"] = data.reason

    canonical_json = json.dumps(snapshot_data, sort_keys=True, separators=(',', ':'))
    priv_pem, _ = get_or_load_root_signing_keys()
    license_obj.snapshot_entitlements = canonical_json
    license_obj.signature = sign_payload(priv_pem, canonical_json.encode("utf-8"))

    fmt = lambda d: d.strftime('%d-%m-%Y')
    history = LicenseHistory(
        license_id=license_obj.id,
        action="VALIDITY_EDITED",
        old_values=json.dumps({
            "valid_from": old_from.isoformat(),
            "valid_until": old_until.isoformat(),
            "grace_period_days": old_grace,
        }, sort_keys=True),
        new_values=json.dumps({
            "valid_from": new_from.isoformat(),
            "valid_until": new_until.isoformat(),
            "grace_period_days": new_grace,
        }, sort_keys=True),
        performed_by_user_id=user_id,
        remarks=(
            f"Koreksi masa berlaku: {fmt(old_from)} s.d. {fmt(old_until)} -> "
            f"{fmt(new_from)} s.d. {fmt(new_until)}. Alasan: {data.reason}."
        )
    )
    db.add(history)
    db.commit()
    db.refresh(license_obj)

    log_audit_event(
        db=db,
        action_category="LICENSE",
        action_name="LICENSE_VALIDITY_EDITED",
        user_id=user_id,
        target_resource=f"license:{license_obj.id}",
        details={
            "old_from": old_from.isoformat(),
            "old_until": old_until.isoformat(),
            "new_from": new_from.isoformat(),
            "new_until": new_until.isoformat(),
            "old_grace": old_grace,
            "new_grace": new_grace,
            "reason": data.reason,
        }
    )
    return license_obj


# ---------------------------------------------------------------------------
# License Status Management (Suspend, Reactivate, Revoke)
# ---------------------------------------------------------------------------

def update_license_status(
    db: Session,
    license_id: UUID,
    data: LicenseStatusUpdate,
    user_id: Optional[UUID] = None
) -> License:
    """Updates license operational status (ACTIVE / SUSPENDED / REVOKED) with audit trail."""
    license_obj = db.query(License).filter(License.id == license_id, License.deleted_at.is_(None)).first()
    if not license_obj:
        raise ValueError("Lisensi tidak ditemukan.")

    allowed = {"ACTIVE", "SUSPENDED", "REVOKED"}
    if data.status not in allowed:
        raise ValueError(f"Status tidak valid: {data.status}. Pilih: {allowed}")

    old_status = license_obj.status
    if has_license_revocation(db, license_obj.id):
        raise ValueError("Lisensi yang telah dicabut tidak dapat diaktifkan kembali atau diubah kembali.")
    if old_status in ("REVOKED", "TERMINATED") and data.status != old_status:
        raise ValueError(f"Lisensi berstatus {old_status} tidak dapat diaktifkan kembali.")
    if old_status == data.status:
        raise ValueError(f"Lisensi sudah berstatus {data.status}.")
    license_obj.status = data.status

    # If Revoked, record in RevocationRecord table (CRL)
    if data.status == "REVOKED" and old_status != "REVOKED":
        revocation = RevocationRecord(
            entity_type="LICENSE",
            entity_id=license_obj.id,
            revocation_code=f"REV-LIC-{secrets.token_hex(4).upper()}",
            reason=data.reason,
            revoked_by_user_id=user_id
        )
        db.add(revocation)

    # Record history
    history = LicenseHistory(
        license_id=license_obj.id,
        action=f"STATUS_{data.status}",
        old_values=old_status,
        new_values=data.status,
        performed_by_user_id=user_id,
        remarks=f"Status lisensi diubah dari {old_status} ke {data.status}. Alasan: {data.reason}"
    )
    db.add(history)
    db.commit()
    db.refresh(license_obj)

    log_audit_event(
        db=db,
        action_category="LICENSE",
        action_name="LICENSE_STATUS_CHANGED",
        user_id=user_id,
        target_resource=f"license:{license_obj.id}",
        details={"from": old_status, "to": data.status, "reason": data.reason}
    )
    return license_obj


# ---------------------------------------------------------------------------
# License Detail & Signature Verification
# ---------------------------------------------------------------------------

def get_license_detail(db: Session, license_id: UUID) -> Optional[Dict[str, Any]]:
    """Assembles full license profile, relations, and verifies digital signature."""
    lic = db.query(License).filter(License.id == license_id, License.deleted_at.is_(None)).first()
    if not lic:
        return None

    # Check digital signature validity
    signature_valid = False
    if lic.signature and lic.snapshot_entitlements:
        _, pub_pem = get_or_load_root_signing_keys()
        signature_valid = verify_signature(
            public_key_pem=pub_pem,
            payload_bytes=lic.snapshot_entitlements.encode("utf-8"),
            signature_b64=lic.signature
        )

    # Linked installations
    linked_installations = []
    for link in lic.installations:
        if link.installation:
            inst = link.installation
            linked_installations.append({
                "id": str(inst.id),
                "installation_code": inst.installation_code,
                "name": inst.name,
                "environment": inst.environment,
                "status": inst.status,
                "is_active_link": link.is_active,
                "activated_at": link.activated_at
            })

    # Modules
    modules = [m.module_code for m in lic.modules if m.is_enabled]

    # Levels
    levels = [l.level_name for l in lic.levels if l.is_allowed]

    # Capacity
    cap_dict = {}
    if lic.capacity:
        cap_dict = {
            "max_members": lic.capacity.max_members,
            "max_accounts": lic.capacity.max_accounts,
            "max_concurrent_users": lic.capacity.max_concurrent_users,
            "max_storage_mb": lic.capacity.max_storage_mb,
            "max_gps_points_per_month": lic.capacity.max_gps_points_per_month
        }

    # History
    history_list = []
    for h in sorted(lic.history, key=lambda x: x.created_at, reverse=True):
        performed_name = h.performed_by.full_name if h.performed_by else "System Superadmin"
        history_list.append({
            "id": h.id,
            "action": h.action,
            "remarks": h.remarks,
            "performed_by_name": performed_name,
            "created_at": h.created_at
        })

    return {
        "id": lic.id,
        "license_key": lic.license_key,
        "customer_id": lic.customer_id,
        "customer_name": lic.customer.organization_name if lic.customer else "Unknown",
        "customer_code": lic.customer.customer_code if lic.customer else "Unknown",
        "package_id": lic.package_id,
        "package_name": lic.package.package_name if lic.package else "Custom",
        "license_type": lic.license_type,
        "status": lic.status,
        "computed_status": compute_license_status(lic),
        "issued_at": lic.issued_at,
        "valid_from": lic.valid_from,
        "valid_until": lic.valid_until,
        "grace_period_days": lic.grace_period_days,
        "max_installations": lic.max_installations,
        "modules": modules,
        "levels": levels,
        "capacity": cap_dict,
        "installations": linked_installations,
        "signature": lic.signature,
        "signature_valid": signature_valid,
        "snapshot_entitlements": lic.snapshot_entitlements,
        "notes": lic.notes,
        "created_at": lic.created_at,
        "history": history_list
    }


def bind_installation_to_license(
    db: Session,
    license_id: UUID,
    installation_id: UUID,
    user_id: Optional[UUID] = None
) -> LicenseInstallation:
    """Binds an installation to an existing commercial license if quota permits."""
    lic = db.query(License).filter(
        License.id == license_id,
        License.deleted_at.is_(None),
    ).with_for_update().first()
    if not lic:
        raise ValueError("Lisensi tidak ditemukan.")
    if has_license_revocation(db, lic.id):
        raise ValueError("Lisensi yang telah dicabut tidak dapat dihubungkan ke instalasi.")

    inst = db.query(Installation).filter(Installation.id == installation_id).first()
    if not inst:
        raise ValueError("Instalasi tidak ditemukan.")

    if inst.customer_id != lic.customer_id:
        raise ValueError("Instalasi bukan milik organisasi pelanggan pemegang lisensi ini.")
    if inst.status != "ACTIVE":
        raise ValueError("Instalasi harus berstatus ACTIVE sebelum dihubungkan ke lisensi.")
    if compute_license_status(lic) != "ACTIVE":
        raise ValueError("Lisensi harus berstatus operasional ACTIVE sebelum dihubungkan.")

    # Check if already linked
    existing = db.query(LicenseInstallation).filter(
        LicenseInstallation.license_id == license_id,
        LicenseInstallation.installation_id == installation_id
    ).first()
    if existing:
        if existing.is_active:
            return existing
        active_count = db.query(LicenseInstallation).filter(
            LicenseInstallation.license_id == license_id,
            LicenseInstallation.is_active == True
        ).count()
        if active_count >= lic.max_installations:
            raise ValueError(
                f"Batas maksimum instalasi ({lic.max_installations}) untuk lisensi ini telah tercapai."
            )
        existing.is_active = True
        link = existing
    else:
        active_count = db.query(LicenseInstallation).filter(
            LicenseInstallation.license_id == license_id,
            LicenseInstallation.is_active == True
        ).count()
        if active_count >= lic.max_installations:
            raise ValueError(
                f"Batas maksimum instalasi ({lic.max_installations}) untuk lisensi ini telah tercapai."
            )
        link = LicenseInstallation(
            license_id=license_id,
            installation_id=installation_id,
            is_active=True
        )
        db.add(link)

    # Record history
    history = LicenseHistory(
        license_id=lic.id,
        action="INSTALLATION_LINKED",
        new_values=inst.installation_code,
        performed_by_user_id=user_id,
        remarks=f"Instalasi '{inst.name}' ({inst.installation_code}) dihubungkan ke lisensi."
    )
    db.add(history)
    db.commit()
    db.refresh(link)
    return link


def soft_delete_license(db: Session, license_id: UUID, user_id: Optional[UUID] = None) -> Optional[License]:
    """Hides a license from operations without removing its audit and validation history."""
    license_obj = db.query(License).filter(
        License.id == license_id,
        License.deleted_at.is_(None),
    ).first()
    if not license_obj:
        return None

    license_obj.deleted_at = datetime.now(timezone.utc)
    license_obj.status = "REVOKED"
    db.add(LicenseHistory(
        license_id=license_obj.id,
        action="DELETED",
        old_values=license_obj.license_key,
        new_values="DELETED",
        performed_by_user_id=user_id,
        remarks="Lisensi dihapus dari daftar operasional (soft-delete).",
    ))
    db.add(RevocationRecord(
        entity_type="LICENSE",
        entity_id=license_obj.id,
        revocation_code=f"DEL-LIC-{secrets.token_hex(4).upper()}",
        reason="Lisensi dihapus dari sistem operasional.",
        revoked_by_user_id=user_id,
    ))
    db.commit()
    db.refresh(license_obj)
    log_audit_event(
        db=db,
        action_category="LICENSE",
        action_name="LICENSE_DELETED",
        user_id=user_id,
        target_resource=f"license:{license_obj.id}",
        details={"license_id": str(license_obj.id), "deleted_at": license_obj.deleted_at.isoformat()},
    )
    return license_obj
