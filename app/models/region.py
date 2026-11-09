"""Regional boundaries and organizational level models for SIMPATI."""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin, utc_now


class Region(Base, UUIDMixin, TimestampMixin):
    """Indonesian administrative boundaries (Provinsi, Kabupaten/Kota, Kecamatan, Desa/Kelurahan)."""
    __tablename__ = "regions"

    region_code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    parent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("regions.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    level: Mapped[str] = mapped_column(String(30), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    children: Mapped[List["Region"]] = relationship("Region", back_populates="parent")
    parent: Mapped[Optional["Region"]] = relationship("Region", back_populates="children", remote_side="Region.id")
    license_regions: Mapped[List["LicenseRegion"]] = relationship(
        "LicenseRegion",
        back_populates="region",
        cascade="all, delete-orphan"
    )


class LicenseRegion(Base, UUIDMixin):
    """Regional territory entitlement assigned to a license."""
    __tablename__ = "license_regions"
    __table_args__ = (
        UniqueConstraint("license_id", "region_id", name="uq_license_region"),
    )

    license_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    region_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("regions.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    include_subregions: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    license: Mapped["License"] = relationship("License", back_populates="regions")
    region: Mapped["Region"] = relationship("Region", back_populates="license_regions")


class LicenseOrganizationalLevel(Base, UUIDMixin):
    """Organizational hierarchy tiers authorized for a license (DPD, DPC, DPS, DPSS)."""
    __tablename__ = "license_levels"
    __table_args__ = (
        UniqueConstraint("license_id", "level_name", name="uq_license_level"),
    )

    license_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("licenses.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    level_name: Mapped[str] = mapped_column(String(30), nullable=False)  # DPD, DPC, DPS, DPSS
    is_allowed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_units: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    license: Mapped["License"] = relationship("License", back_populates="levels")
