"""Operational logs, periodic validations, history audit, and system settings."""

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, Text, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin, utc_now


class LicenseValidation(Base, UUIDMixin):
    """Periodic validation checks performed by SIMPATI instances."""
    __tablename__ = "license_validations"

    license_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("installations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    validation_token: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    request_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    validation_status: Mapped[str] = mapped_column(String(30), nullable=False)  # VALID, GRACE_PERIOD, RESTRICTED, INVALID, REVOKED
    signed_token_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    next_validation_due: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    validated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    license: Mapped["License"] = relationship("License", back_populates="validations")
    installation: Mapped["Installation"] = relationship("Installation", back_populates="validations")


class LicenseHistory(Base, UUIDMixin):
    """Complete audit trail of state and lifecycle transitions for each license."""
    __tablename__ = "license_history"

    license_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    old_values: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_values: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    performed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("license_users.id", ondelete="SET NULL"),
        nullable=True
    )
    remarks: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    license: Mapped["License"] = relationship("License", back_populates="history")
    performed_by: Mapped[Optional["LicenseUser"]] = relationship("LicenseUser")


class LicenseAuditLog(Base, UUIDMixin):
    """Comprehensive system-wide administrative audit trail."""
    __tablename__ = "license_audit_logs"

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("license_users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    action_category: Mapped[str] = mapped_column(String(30), nullable=False, index=True)  # AUTH, LICENSE, INSTALLATION, CUSTOMER, SECURITY, SYSTEM
    action_name: Mapped[str] = mapped_column(String(100), nullable=False)
    target_resource: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="SUCCESS", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    user: Mapped[Optional["LicenseUser"]] = relationship("LicenseUser", back_populates="audit_logs")


class SystemSetting(Base, UUIDMixin):
    """System-wide configuration parameters."""
    __tablename__ = "system_settings"

    setting_key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    setting_value: Mapped[str] = mapped_column(Text, nullable=False)
    data_type: Mapped[str] = mapped_column(String(20), default="STRING", nullable=False)  # STRING, INTEGER, BOOLEAN, JSON
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("license_users.id", ondelete="SET NULL"),
        nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    updater: Mapped[Optional["LicenseUser"]] = relationship("LicenseUser")
