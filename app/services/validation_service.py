"""License validation, heartbeat, and Restricted Mode enforcement service."""

import json
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models.license import License, LicenseInstallation
from app.models.installation import Installation
from app.models.operations import LicenseValidation
from app.services.license_service import compute_license_status
from app.security.crypto import generate_secure_token
from app.services.audit_service import log_audit_event


def validate_installation_license(
    db: Session,
    license_key: str,
    installation_code: str,
    request_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Validates an installation against its commercial license, applying grace period and Restricted Mode rules."""
    license_obj = db.query(License).filter(License.license_key == license_key).first()
    if not license_obj:
        return {
            "validation_status": "INVALID",
            "message": "Lisensi tidak ditemukan dalam sistem pusat.",
            "restricted_mode": True,
            "allowed_actions": ["VIEW_ONLY", "EXPORT_DATA", "LOGIN"]
        }

    installation = db.query(Installation).filter(Installation.installation_code == installation_code).first()
    if not installation:
        return {
            "validation_status": "UNAUTHORIZED_INSTALLATION",
            "message": "Kode instalasi SIMPATI belum terdaftar di License Manager.",
            "restricted_mode": True,
            "allowed_actions": ["VIEW_ONLY", "EXPORT_DATA", "LOGIN"]
        }

    now = datetime.now(timezone.utc)
    status = compute_license_status(license_obj)
    is_restricted = status in ["RESTRICTED", "SUSPENDED", "EXPIRED", "REVOKED"]

    # Calculate next validation due (typically 24 hours)
    next_due = now + timedelta(hours=24)
    validation_token = f"val_{secrets.token_urlsafe(32)}"

    # Parse entitlements snapshot
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

    validation_payload = {
        "license_key": license_key,
        "installation_code": installation_code,
        "validation_status": status,
        "is_restricted_mode": is_restricted,
        "validated_at": now.isoformat(),
        "next_validation_due": next_due.isoformat(),
        "allowed_modules": allowed_modules,
        "allowed_levels": allowed_levels,
        "capacity": capacity_data,
        "restricted_rules": {
            "login_allowed": True,
            "read_data_allowed": True,
            "export_backup_allowed": True,
            "write_mutations_blocked": is_restricted,
            "account_modifications_blocked": is_restricted,
            "uploads_blocked": is_restricted,
            "public_registration_blocked": is_restricted
        }
    }

    # Record validation event
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

    # Update installation heartbeat
    installation.last_heartbeat_at = now
    db.commit()

    return {
        "validation_token": validation_token,
        "validation_status": status,
        "license_key": license_key,
        "installation_code": installation_code,
        "next_validation_due": next_due.isoformat(),
        "is_restricted_mode": is_restricted,
        "allowed_modules": allowed_modules,
        "allowed_levels": allowed_levels,
        "capacity": capacity_data,
        "payload": validation_payload
    }
