"""License validation, heartbeat, and Restricted Mode enforcement service."""

import base64
import json
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.models.license import License, LicenseInstallation
from app.models.installation import Installation
from app.models.operations import LicenseValidation
from app.services.license_service import compute_license_status, get_or_load_root_signing_keys
from app.security.crypto import generate_secure_token
from app.services.audit_service import log_audit_event


def _sign_payload_canonical(payload_dict: Dict[str, Any]) -> str:
    """Signs canonical JSON bytes of payload_dict using root Ed25519 private key."""
    priv_pem, _ = get_or_load_root_signing_keys()
    priv_key = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
    canonical_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature_bytes = priv_key.sign(canonical_bytes)
    return signature_bytes.hex()


def validate_installation_license(
    db: Session,
    license_key: str,
    installation_code: str,
    request_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Validates an installation against its commercial license, applying binding checks,

    grace period, and Restricted Mode rules. Digitally signs the response payload with Ed25519.
    """
    now = datetime.now(timezone.utc)
    validation_token = f"val_{secrets.token_urlsafe(32)}"

    # 1. License Lookup
    license_obj = db.query(License).filter(License.license_key == license_key).first()
    if not license_obj:
        rej_payload = {
            "license_key": license_key,
            "installation_code": installation_code,
            "validation_status": "INVALID",
            "message": "Lisensi tidak ditemukan dalam sistem pusat.",
            "is_restricted_mode": True,
            "validated_at": now.isoformat(),
            "next_validation_due": (now + timedelta(hours=1)).isoformat(),
            "allowed_modules": [],
            "allowed_levels": [],
            "capacity": {},
            "restricted_rules": {
                "login_allowed": True,
                "read_data_allowed": True,
                "export_backup_allowed": True,
                "write_mutations_blocked": True,
                "account_modifications_blocked": True,
                "uploads_blocked": True,
                "public_registration_blocked": True
            }
        }
        sig = _sign_payload_canonical(rej_payload)
        return {
            "validation_token": validation_token,
            "validation_status": "INVALID",
            "message": "Lisensi tidak ditemukan dalam sistem pusat.",
            "is_restricted_mode": True,
            "allowed_modules": [],
            "allowed_levels": [],
            "capacity": {},
            "restricted_rules": rej_payload["restricted_rules"],
            "next_validation_due": rej_payload["next_validation_due"],
            "payload": rej_payload,
            "signature": sig
        }

    # 2. Installation Lookup
    installation = db.query(Installation).filter(Installation.installation_code == installation_code).first()
    if not installation:
        rej_payload = {
            "license_key": license_key,
            "installation_code": installation_code,
            "validation_status": "UNAUTHORIZED_INSTALLATION",
            "message": "Kode instalasi SIMPATI belum terdaftar di License Manager.",
            "is_restricted_mode": True,
            "validated_at": now.isoformat(),
            "next_validation_due": (now + timedelta(hours=1)).isoformat(),
            "allowed_modules": [],
            "allowed_levels": [],
            "capacity": {},
            "restricted_rules": {
                "login_allowed": True,
                "read_data_allowed": True,
                "export_backup_allowed": True,
                "write_mutations_blocked": True,
                "account_modifications_blocked": True,
                "uploads_blocked": True,
                "public_registration_blocked": True
            }
        }
        sig = _sign_payload_canonical(rej_payload)
        return {
            "validation_token": validation_token,
            "validation_status": "UNAUTHORIZED_INSTALLATION",
            "message": "Kode instalasi SIMPATI belum terdaftar di License Manager.",
            "is_restricted_mode": True,
            "allowed_modules": [],
            "allowed_levels": [],
            "capacity": {},
            "restricted_rules": rej_payload["restricted_rules"],
            "next_validation_due": rej_payload["next_validation_due"],
            "payload": rej_payload,
            "signature": sig
        }

    # 3. License-Installation Binding Verification
    binding = (
        db.query(LicenseInstallation)
        .filter(
            LicenseInstallation.license_id == license_obj.id,
            LicenseInstallation.installation_id == installation.id,
            LicenseInstallation.is_active == True
        )
        .first()
    )
    if not binding:
        rej_payload = {
            "license_key": license_key,
            "installation_code": installation_code,
            "validation_status": "UNBOUND_INSTALLATION",
            "message": f"Instalasi '{installation_code}' tidak memiliki ikatan aktif dengan lisensi '{license_key}'. Lisensi milik instalasi lain atau belum diikatkan.",
            "is_restricted_mode": True,
            "validated_at": now.isoformat(),
            "next_validation_due": (now + timedelta(hours=1)).isoformat(),
            "allowed_modules": [],
            "allowed_levels": [],
            "capacity": {},
            "restricted_rules": {
                "login_allowed": True,
                "read_data_allowed": True,
                "export_backup_allowed": True,
                "write_mutations_blocked": True,
                "account_modifications_blocked": True,
                "uploads_blocked": True,
                "public_registration_blocked": True
            }
        }
        sig = _sign_payload_canonical(rej_payload)
        return {
            "validation_token": validation_token,
            "validation_status": "UNBOUND_INSTALLATION",
            "message": rej_payload["message"],
            "is_restricted_mode": True,
            "allowed_modules": [],
            "allowed_levels": [],
            "capacity": {},
            "restricted_rules": rej_payload["restricted_rules"],
            "next_validation_due": rej_payload["next_validation_due"],
            "payload": rej_payload,
            "signature": sig
        }

    # 4. Compute Status & Restricted Mode
    status = compute_license_status(license_obj)
    is_restricted = status in ["RESTRICTED", "SUSPENDED", "EXPIRED", "REVOKED"]

    # Calculate next validation due (typically 24 hours)
    next_due = now + timedelta(hours=24)

    # 5. Parse Entitlements Snapshot
    entitlements = {}
    if license_obj.snapshot_entitlements:
        try:
            entitlements = json.loads(license_obj.snapshot_entitlements)
        except Exception:
            pass

    allowed_modules = entitlements.get("modules", [m.module_code for m in license_obj.modules])
    allowed_levels = entitlements.get("levels", [l.level_name for l in license_obj.levels])
    capacity_data = entitlements.get("capacity", {
        "max_members": license_obj.capacity.max_members if license_obj.capacity else 50000,
        "max_accounts": license_obj.capacity.max_accounts if license_obj.capacity else 200,
        "max_concurrent_users": license_obj.capacity.max_concurrent_users if license_obj.capacity else 25,
        "max_storage_mb": license_obj.capacity.max_storage_mb if license_obj.capacity else 20480,
    })

    restricted_rules = {
        "login_allowed": True,
        "read_data_allowed": True,
        "export_backup_allowed": True,
        "write_mutations_blocked": is_restricted,
        "account_modifications_blocked": is_restricted,
        "uploads_blocked": is_restricted,
        "public_registration_blocked": is_restricted
    }

    pkg_name = license_obj.package.package_name if license_obj.package else "Paket Lengkap Nasional Enterprise"
    cust_name = license_obj.customer.organization_name if license_obj.customer else "Ikatan Persaudaraan Lima Lima Lima (555)"
    v_from = license_obj.valid_from.isoformat() if license_obj.valid_from else now.isoformat()
    v_until = license_obj.valid_until.isoformat() if license_obj.valid_until else (now + timedelta(days=365)).isoformat()

    validation_payload = {
        "product_name": "SIMPATI 555",
        "package_name": pkg_name,
        "customer_name": cust_name,
        "territory_scope": "Nasional & Wilayah Terdaftar",
        "license_key": license_key,
        "installation_code": installation_code,
        "valid_from": v_from,
        "valid_until": v_until,
        "validation_status": status,
        "is_restricted_mode": is_restricted,
        "validated_at": now.isoformat(),
        "next_validation_due": next_due.isoformat(),
        "allowed_modules": allowed_modules,
        "allowed_levels": allowed_levels,
        "capacity": capacity_data,
        "restricted_rules": restricted_rules
    }

    # 6. Ed25519 Signature Generation
    signature_hex = _sign_payload_canonical(validation_payload)

    # 7. Record Validation Event
    val_record = LicenseValidation(
        license_id=license_obj.id,
        installation_id=installation.id,
        validation_token=validation_token,
        request_ip=request_ip,
        validation_status=status,
        signed_token_payload=json.dumps(validation_payload),
        next_validation_due=next_due,
        validated_at=now
    )
    db.add(val_record)

    # 8. Update Installation Heartbeat
    installation.last_heartbeat_at = now
    db.commit()

    signature_b64 = base64.b64encode(bytes.fromhex(signature_hex)).decode("ascii")

    return {
        "validation_token": validation_token,
        "validation_status": status,
        "product_name": "SIMPATI 555",
        "package_name": pkg_name,
        "customer_name": cust_name,
        "territory_scope": "Nasional & Wilayah Terdaftar",
        "license_key": license_key,
        "installation_code": installation_code,
        "valid_from": v_from,
        "valid_until": v_until,
        "next_validation_due": next_due.isoformat(),
        "is_restricted_mode": is_restricted,
        "allowed_modules": allowed_modules,
        "allowed_levels": allowed_levels,
        "capacity": capacity_data,
        "restricted_rules": restricted_rules,
        "payload": validation_payload,
        "signature": signature_hex,
        "signature_format": "hex",
        "signature_base64": signature_b64
    }


def activate_client_license(
    db: Session,
    license_key: str,
    server_domain: str | None = None,
    server_ip: str | None = None,
    instance_name: str | None = None,
    environment: str = "PRODUCTION",
) -> Dict[str, Any]:
    """Mengaktifkan lisensi dari sisi klien SIMPATI 555 menggunakan License Key.

    Otomatis:
    1. Memverifikasi validitas License Key, pelanggan, status, dan masa berlaku.
    2. Menghubungkan atau membuat identitas instalasi secara otomatis.
    3. Menerbitkan/merotasi kredensial M2M (client_id & client_secret) yang aman.
    4. Mengaktifkan lisensi jika sebelumnya berstatus DRAFT.
    5. Menjalankan validasi awal lengkap dengan snapshot dan tanda tangan digital Ed25519.
    """
    from app.models.customer import Customer
    from app.models.installation import Installation, InstallationCredential
    from app.services.installation_service import (
        generate_installation_code,
        generate_client_credentials,
        rotate_installation_credentials,
    )
    from app.services.license_service import ensure_utc

    key_clean = (license_key or "").strip()
    if not key_clean:
        raise ValueError("License Key tidak boleh kosong.")

    # 1. Cari Lisensi
    lic = db.query(License).filter(License.license_key == key_clean).first()
    if not lic:
        raise ValueError(
            f"License Key '{key_clean}' tidak ditemukan dalam sistem pusat. "
            "Pastikan License Key yang dimasukkan benar dan telah diterbitkan oleh administrator."
        )

    # 2. Periksa Organisasi Pelanggan
    customer = db.query(Customer).filter(Customer.id == lic.customer_id).first()
    if not customer or customer.status != "ACTIVE":
        raise ValueError("Organisasi pelanggan pemilik lisensi ini sedang dinonaktifkan.")

    # 3. Periksa Status Lisensi & Masa Berlaku
    now = datetime.now(timezone.utc)
    if lic.status in ["REVOKED", "TERMINATED"]:
        raise ValueError(f"Lisensi ini berstatus '{lic.status}' dan telah dicabut. Tidak dapat diaktifkan.")
    if lic.status == "SUSPENDED":
        raise ValueError("Lisensi ini sedang ditangguhkan (SUSPENDED). Hubungi administrator SIMPATI.")

    v_until = ensure_utc(lic.valid_until)
    if v_until and v_until < now:
        raise ValueError("Masa berlaku lisensi ini telah kedaluwarsa.")

    # 4. Hubungkan atau Buat Instalasi
    existing_link = (
        db.query(LicenseInstallation)
        .filter(LicenseInstallation.license_id == lic.id, LicenseInstallation.is_active == True)
        .first()
    )

    if existing_link:
        inst = db.query(Installation).filter(Installation.id == existing_link.installation_id).first()
        if not inst:
            raise ValueError("Data instalasi terdaftar tidak ditemukan.")
        # Rotasi kredensial agar klien mendapatkan plaintext client_secret baru
        cred_res = rotate_installation_credentials(db, inst.id)
        if not cred_res:
            raise ValueError("Gagal memperbarui kredensial instalasi.")
        client_id, client_secret = cred_res
        if server_domain:
            inst.server_domain = server_domain
        if server_ip:
            inst.server_ip = server_ip
        inst.status = "ACTIVE"
    else:
        active_count = (
            db.query(LicenseInstallation)
            .filter(LicenseInstallation.license_id == lic.id, LicenseInstallation.is_active == True)
            .count()
        )
        if active_count >= lic.max_installations:
            raise ValueError(
                f"Batas maksimum instalasi ({lic.max_installations}) untuk lisensi ini sudah terpenuhi."
            )

        inst_code = generate_installation_code(customer.customer_code)
        inst_title = instance_name or f"Instalasi SIMPATI {customer.organization_name}"
        inst = Installation(
            customer_id=customer.id,
            installation_code=inst_code,
            name=inst_title,
            server_domain=server_domain,
            server_ip=server_ip,
            environment=environment,
            status="ACTIVE",
        )
        db.add(inst)
        db.flush()

        client_id, client_secret, secret_hash = generate_client_credentials()
        cred = InstallationCredential(
            installation_id=inst.id,
            client_id=client_id,
            client_secret_hash=secret_hash,
            is_active=True,
        )
        db.add(cred)

        new_link = LicenseInstallation(
            license_id=lic.id,
            installation_id=inst.id,
            is_active=True,
        )
        db.add(new_link)

    # Aktifkan lisensi jika statusnya masih DRAFT
    if lic.status == "DRAFT":
        lic.status = "ACTIVE"

    db.commit()
    db.refresh(inst)
    db.refresh(lic)

    # 5. Lakukan validasi awal untuk snapshot lisensi terverifikasi
    val_res = validate_installation_license(
        db=db,
        license_key=lic.license_key,
        installation_code=inst.installation_code,
        request_ip=server_ip or "127.0.0.1",
    )

    return {
        "success": True,
        "message": "Lisensi SIMPATI 555 berhasil diaktifkan.",
        "license_key": lic.license_key,
        "installation_code": inst.installation_code,
        "client_id": client_id,
        "client_secret": client_secret,
        "validation_result": val_res,
    }
