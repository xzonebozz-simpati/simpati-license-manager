"""Models package exposing all entities and Base metadata."""

from app.models.base import Base, UUIDMixin, TimestampMixin, utc_now
from app.models.user import LicenseUser, LicenseUserSession
from app.models.customer import Customer
from app.models.installation import Installation, InstallationCredential, InstallationEvent
from app.models.catalog import LicensePackage, ModuleRegistry, ModuleDependency, PackageModule
from app.models.license import License, LicenseInstallation, LicenseModule, LicenseCapacity
from app.models.region import Region, LicenseRegion, LicenseOrganizationalLevel
from app.models.security import SigningKey, RevocationRecord, ApiSecurityLog
from app.models.operations import LicenseValidation, ValidationNonce, LicenseHistory, LicenseAuditLog, SystemSetting

__all__ = [
    "Base",
    "UUIDMixin",
    "TimestampMixin",
    "utc_now",
    # User & Session
    "LicenseUser",
    "LicenseUserSession",
    # Customer
    "Customer",
    # Installation
    "Installation",
    "InstallationCredential",
    "InstallationEvent",
    # Catalog
    "LicensePackage",
    "ModuleRegistry",
    "ModuleDependency",
    "PackageModule",
    # License & Capacity
    "License",
    "LicenseInstallation",
    "LicenseModule",
    "LicenseCapacity",
    # Regions & Levels
    "Region",
    "LicenseRegion",
    "LicenseOrganizationalLevel",
    # Security & Keys
    "SigningKey",
    "RevocationRecord",
    "ApiSecurityLog",
    # Operations & Auditing
    "LicenseValidation",
    "ValidationNonce",
    "LicenseHistory",
    "LicenseAuditLog",
    "SystemSetting",
]
