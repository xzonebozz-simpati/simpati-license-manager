"""Product catalog, modules, and packaging models for SIMPATI."""

import uuid
from typing import Optional, List
from sqlalchemy import String, Boolean, Text, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin


class LicensePackage(Base, UUIDMixin, TimestampMixin):
    """Standard commercial tier package (e.g., STARTER, PROFESSIONAL, ENTERPRISE)."""
    __tablename__ = "license_packages"

    package_code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    default_tier: Mapped[str] = mapped_column(String(30), default="STANDARD", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    package_modules: Mapped[List["PackageModule"]] = relationship(
        "PackageModule",
        back_populates="package",
        cascade="all, delete-orphan"
    )
    licenses: Mapped[List["License"]] = relationship(
        "License",
        back_populates="package"
    )


class ModuleRegistry(Base, UUIDMixin, TimestampMixin):
    """Master registry of functional application modules (CORE, DATA, SURVEI_GPS, etc.)."""
    __tablename__ = "module_registry"

    module_code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    module_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_core: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    package_links: Mapped[List["PackageModule"]] = relationship(
        "PackageModule",
        back_populates="module",
        cascade="all, delete-orphan"
    )
    dependencies: Mapped[List["ModuleDependency"]] = relationship(
        "ModuleDependency",
        foreign_keys="ModuleDependency.module_id",
        back_populates="module",
        cascade="all, delete-orphan"
    )


class ModuleDependency(Base, UUIDMixin, TimestampMixin):
    """Defines prerequisite modules required for a module to function."""
    __tablename__ = "module_dependencies"
    __table_args__ = (
        UniqueConstraint("module_id", "required_module_id", name="uq_module_dependency"),
    )

    module_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_registry.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    required_module_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_registry.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Relationships
    module: Mapped["ModuleRegistry"] = relationship(
        "ModuleRegistry",
        foreign_keys=[module_id],
        back_populates="dependencies"
    )
    required_module: Mapped["ModuleRegistry"] = relationship(
        "ModuleRegistry",
        foreign_keys=[required_module_id]
    )


class PackageModule(Base, UUIDMixin, TimestampMixin):
    """Association linking license packages with their default module bundles."""
    __tablename__ = "package_modules"
    __table_args__ = (
        UniqueConstraint("package_id", "module_id", name="uq_package_module"),
    )

    package_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("license_packages.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    module_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("module_registry.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    is_mandatory: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    package: Mapped["LicensePackage"] = relationship("LicensePackage", back_populates="package_modules")
    module: Mapped["ModuleRegistry"] = relationship("ModuleRegistry", back_populates="package_links")
