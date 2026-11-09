"""Cryptographic keys, revocation records, and security telemetry models."""

import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, Boolean, DateTime, Text, ForeignKey, func, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin, utc_now


class SigningKey(Base, UUIDMixin, TimestampMixin):
    """Cryptographic signing key metadata (Private keys never stored as plain text)."""
    __tablename__ = "signing_keys"

    key_identifier: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(20), default="Ed25519", nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    key_vault_reference: Mapped[str] = mapped_column(String(150), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RevocationRecord(Base, UUIDMixin):
    """CRL (Certificate Revocation List / Blacklist) for licenses and installations."""
    __tablename__ = "revocation_records"

    entity_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)  # LICENSE, INSTALLATION, SIGNING_KEY
    entity_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    revocation_code: Mapped[str] = mapped_column(String(50), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )
    revoked_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("license_users.id", ondelete="SET NULL"),
        nullable=True
    )

    # Relationships
    revoked_by: Mapped[Optional["LicenseUser"]] = relationship("LicenseUser")


class ApiSecurityLog(Base, UUIDMixin):
    """Security anomaly and unauthorized access attempt log."""
    __tablename__ = "api_security_logs"

    endpoint: Mapped[str] = mapped_column(String(200), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    client_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    response_code: Mapped[int] = mapped_column(Integer, nullable=False)
    failure_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    headers_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )
