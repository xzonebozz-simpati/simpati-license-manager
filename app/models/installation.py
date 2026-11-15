"""Installation and deployment identity models for SIMPATI License Manager."""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Boolean, DateTime, Text, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin, utc_now


class Installation(Base, UUIDMixin, TimestampMixin):
    """Customer-managed SIMPATI server deployment/instance."""
    __tablename__ = "installations"

    # Nullable only to preserve legacy installations that predate customer links.
    # New registrations still require customer_id in InstallationCreate/service validation.
    customer_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("customers.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    installation_code: Mapped[str] = mapped_column(String(60), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    server_domain: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    server_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    environment: Mapped[str] = mapped_column(String(30), default="PRODUCTION", nullable=False)
    public_key_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hardware_signature: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="REGISTERED", nullable=False)
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    customer: Mapped[Optional["Customer"]] = relationship("Customer", back_populates="installations")
    credentials: Mapped[List["InstallationCredential"]] = relationship(
        "InstallationCredential",
        back_populates="installation",
        cascade="all, delete-orphan"
    )
    events: Mapped[List["InstallationEvent"]] = relationship(
        "InstallationEvent",
        back_populates="installation",
        cascade="all, delete-orphan"
    )
    license_links: Mapped[List["LicenseInstallation"]] = relationship(
        "LicenseInstallation",
        back_populates="installation",
        cascade="all, delete-orphan"
    )
    validations: Mapped[List["LicenseValidation"]] = relationship(
        "LicenseValidation",
        back_populates="installation",
        cascade="all, delete-orphan"
    )


class InstallationCredential(Base, UUIDMixin):
    """API credentials for installation identity authentication."""
    __tablename__ = "installation_credentials"

    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("installations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    client_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    client_secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    installation: Mapped["Installation"] = relationship("Installation", back_populates="credentials")


class InstallationEvent(Base, UUIDMixin):
    """Telemetry and operational events sent by installations."""
    __tablename__ = "installation_events"

    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("installations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    installation: Mapped["Installation"] = relationship("Installation", back_populates="events")
