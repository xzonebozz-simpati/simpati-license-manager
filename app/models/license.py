"""Commercial license, capacity, and entitlement models for SIMPATI."""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, Boolean, DateTime, Text, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin, utc_now


class License(Base, UUIDMixin, TimestampMixin):
    """Central commercial license granted to a customer organization."""
    __tablename__ = "licenses"

    license_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    customer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("customers.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )
    package_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("license_packages.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )
    license_type: Mapped[str] = mapped_column(String(30), default="COMMERCIAL", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="DRAFT", nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    grace_period_days: Mapped[int] = mapped_column(Integer, default=7, nullable=False)
    max_installations: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    snapshot_entitlements: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    # Relationships
    customer: Mapped["Customer"] = relationship("Customer", back_populates="licenses")
    package: Mapped["LicensePackage"] = relationship("LicensePackage", back_populates="licenses")
    installations: Mapped[List["LicenseInstallation"]] = relationship(
        "LicenseInstallation",
        back_populates="license",
        cascade="all, delete-orphan"
    )
    modules: Mapped[List["LicenseModule"]] = relationship(
        "LicenseModule",
        back_populates="license",
        cascade="all, delete-orphan"
    )
    capacity: Mapped[Optional["LicenseCapacity"]] = relationship(
        "LicenseCapacity",
        back_populates="license",
        uselist=False,
        cascade="all, delete-orphan"
    )
    regions: Mapped[List["LicenseRegion"]] = relationship(
        "LicenseRegion",
        back_populates="license",
        cascade="all, delete-orphan"
    )
    levels: Mapped[List["LicenseOrganizationalLevel"]] = relationship(
        "LicenseOrganizationalLevel",
        back_populates="license",
        cascade="all, delete-orphan"
    )
    validations: Mapped[List["LicenseValidation"]] = relationship(
        "LicenseValidation",
        back_populates="license",
        cascade="all, delete-orphan"
    )
    history: Mapped[List["LicenseHistory"]] = relationship(
        "LicenseHistory",
        back_populates="license",
        cascade="all, delete-orphan"
    )


class LicenseInstallation(Base, UUIDMixin):
    """Binds an authorized installation to a commercial license."""
    __tablename__ = "license_installations"
    __table_args__ = (
        UniqueConstraint("license_id", "installation_id", name="uq_license_installation"),
    )

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
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    license: Mapped["License"] = relationship("License", back_populates="installations")
    installation: Mapped["Installation"] = relationship("Installation", back_populates="license_links")


class LicenseModule(Base, UUIDMixin):
    """Specific active module granted inside a license snapshot."""
    __tablename__ = "license_modules"
    __table_args__ = (
        UniqueConstraint("license_id", "module_code", name="uq_license_module"),
    )

    license_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    module_code: Mapped[str] = mapped_column(String(50), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    custom_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    license: Mapped["License"] = relationship("License", back_populates="modules")


class LicenseCapacity(Base, UUIDMixin, TimestampMixin):
    """Capacity and quota entitlements associated with a license."""
    __tablename__ = "license_capacity"

    license_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("licenses.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True
    )
    max_members: Mapped[int] = mapped_column(Integer, default=50000, nullable=False)
    max_accounts: Mapped[int] = mapped_column(Integer, default=200, nullable=False)
    max_concurrent_users: Mapped[int] = mapped_column(Integer, default=25, nullable=False)
    max_storage_mb: Mapped[int] = mapped_column(Integer, default=20480, nullable=False)
    max_gps_points_per_month: Mapped[int] = mapped_column(Integer, default=100000, nullable=False)
    custom_quotas: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    license: Mapped["License"] = relationship("License", back_populates="capacity")
