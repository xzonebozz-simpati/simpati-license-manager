"""Audit logging service for tracking administrative activities and security events."""

import json
from typing import Optional, Any, Dict
from uuid import UUID
from sqlalchemy.orm import Session
from app.models.operations import LicenseAuditLog


def log_audit_event(
    db: Session,
    action_category: str,
    action_name: str,
    user_id: Optional[UUID] = None,
    ip_address: Optional[str] = None,
    target_resource: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    status: str = "SUCCESS"
) -> LicenseAuditLog:
    """Records an administrative audit log entry."""
    details_str = json.dumps(details, default=str) if details is not None else None

    log_entry = LicenseAuditLog(
        user_id=user_id,
        ip_address=ip_address,
        action_category=action_category,
        action_name=action_name,
        target_resource=target_resource,
        details=details_str,
        status=status
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
