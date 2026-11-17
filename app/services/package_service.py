"""License package catalog management service."""

import json
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID
from sqlalchemy.orm import Session

from app.models.catalog import LicensePackage, PackageModule, ModuleRegistry
from app.models.license import License
from app.schemas.package import PackageCreate, PackageUpdate
from app.services.audit_service import log_audit_event


def get_all_packages(db: Session, skip: int = 0, limit: int = 100) -> List[LicensePackage]:
    """Retrieves all commercial packages ordered by creation date."""
    return db.query(LicensePackage).order_by(LicensePackage.created_at.desc()).offset(skip).limit(limit).all()


def get_package_by_id(db: Session, package_id: UUID) -> Optional[LicensePackage]:
    """Finds a package by UUID primary key."""
    return db.query(LicensePackage).filter(LicensePackage.id == package_id).first()


def get_package_by_code(db: Session, package_code: str) -> Optional[LicensePackage]:
    """Finds a package by unique code."""
    return db.query(LicensePackage).filter(LicensePackage.package_code == package_code).first()


def create_package(
    db: Session,
    data: PackageCreate,
    user_id: Optional[UUID] = None
) -> LicensePackage:
    """Creates a new commercial package and associates default modules."""
    existing = get_package_by_code(db, data.package_code.strip().upper())
    if existing:
        raise ValueError(f"Kode paket '{data.package_code}' sudah terdaftar.")

    # Save flexible commercial config (pricing/levels/capacity) in description or settings if not column
    config_metadata = {
        "price_amount": data.price_amount,
        "billing_period": data.billing_period,
        "default_max_members": data.default_max_members,
        "default_levels": data.levels
    }
    
    # Prepend or store config JSON in description metadata if needed, or maintain clean description
    desc_text = data.description or ""
    if config_metadata:
        desc_payload = f"{desc_text}\n<!--CONFIG:{json.dumps(config_metadata)}-->"
    else:
        desc_payload = desc_text

    package = LicensePackage(
        package_code=data.package_code.strip().upper(),
        package_name=data.package_name.strip(),
        description=desc_payload,
        default_tier=data.default_tier.strip().upper(),
        is_active=data.is_active
    )
    db.add(package)
    db.flush()

    # Link selected modules
    for mod_code in data.modules:
        module = db.query(ModuleRegistry).filter(ModuleRegistry.module_code == mod_code.strip()).first()
        if module:
            link = PackageModule(
                package_id=package.id,
                module_id=module.id,
                is_mandatory=(module.is_core or mod_code == "CORE")
            )
            db.add(link)

    db.commit()
    db.refresh(package)

    log_audit_event(
        db=db,
        action_category="PACKAGE",
        action_name="PACKAGE_CREATED",
        user_id=user_id,
        target_resource=f"package:{package.package_code}",
        details={
            "package_name": package.package_name,
            "tier": package.default_tier,
            "modules_count": len(data.modules)
        }
    )
    return package


def update_package(
    db: Session,
    package_id: UUID,
    data: PackageUpdate,
    user_id: Optional[UUID] = None
) -> Optional[LicensePackage]:
    """Updates attributes of an existing package and synchronizes modules."""
    package = get_package_by_id(db, package_id)
    if not package:
        return None

    changes: Dict[str, Any] = {}
    if data.package_name is not None and data.package_name.strip() != package.package_name:
        changes["package_name"] = {"from": package.package_name, "to": data.package_name.strip()}
        package.package_name = data.package_name.strip()

    if data.default_tier is not None and data.default_tier.strip().upper() != package.default_tier:
        changes["default_tier"] = {"from": package.default_tier, "to": data.default_tier.strip().upper()}
        package.default_tier = data.default_tier.strip().upper()

    if data.is_active is not None and data.is_active != package.is_active:
        changes["is_active"] = {"from": package.is_active, "to": data.is_active}
        package.is_active = data.is_active

    if data.description is not None:
        # Preserve or update config metadata
        clean_desc = data.description
        existing_cfg = _extract_package_config(package.description or "")
        if data.price_amount is not None:
            existing_cfg["price_amount"] = data.price_amount
        if data.billing_period is not None:
            existing_cfg["billing_period"] = data.billing_period
        if data.default_max_members is not None:
            existing_cfg["default_max_members"] = data.default_max_members
        if data.levels is not None:
            existing_cfg["default_levels"] = data.levels

        package.description = f"{clean_desc}\n<!--CONFIG:{json.dumps(existing_cfg)}-->"

    # Synchronize modules if provided
    if data.modules is not None:
        # Remove old links
        db.query(PackageModule).filter(PackageModule.package_id == package_id).delete()
        for mod_code in data.modules:
            module = db.query(ModuleRegistry).filter(ModuleRegistry.module_code == mod_code.strip()).first()
            if module:
                link = PackageModule(
                    package_id=package.id,
                    module_id=module.id,
                    is_mandatory=(module.is_core or mod_code == "CORE")
                )
                db.add(link)
        changes["modules"] = data.modules

    db.commit()
    db.refresh(package)

    if changes:
        log_audit_event(
            db=db,
            action_category="PACKAGE",
            action_name="PACKAGE_UPDATED",
            user_id=user_id,
            target_resource=f"package:{package.package_code}",
            details=changes
        )
    return package


def set_package_status(
    db: Session,
    package_id: UUID,
    is_active: bool,
    user_id: Optional[UUID] = None
) -> Optional[LicensePackage]:
    """Activates or deactivates a package."""
    package = get_package_by_id(db, package_id)
    if not package:
        return None

    old_status = package.is_active
    package.is_active = is_active
    db.commit()
    db.refresh(package)

    log_audit_event(
        db=db,
        action_category="PACKAGE",
        action_name="PACKAGE_STATUS_CHANGED",
        user_id=user_id,
        target_resource=f"package:{package.package_code}",
        details={"from": old_status, "to": is_active}
    )
    return package


def get_package_detail(db: Session, package_id: UUID) -> Optional[Dict[str, Any]]:
    """Retrieves full package profile, active modules, config metadata, and usage count."""
    package = get_package_by_id(db, package_id)
    if not package:
        return None

    modules = []
    for pm in package.package_modules:
        if pm.module:
            modules.append({
                "module_code": pm.module.module_code,
                "module_name": pm.module.module_name,
                "is_core": pm.module.is_core,
                "is_mandatory": pm.is_mandatory
            })

    # Licenses using this package
    total_licenses = db.query(License).filter(
        License.package_id == package_id,
        License.deleted_at.is_(None),
    ).count()

    raw_desc, config = _parse_description_and_config(package.description or "")

    return {
        "id": package.id,
        "package_code": package.package_code,
        "package_name": package.package_name,
        "description": raw_desc,
        "default_tier": package.default_tier,
        "is_active": package.is_active,
        "created_at": package.created_at,
        "updated_at": package.updated_at,
        "modules": [m["module_code"] for m in modules],
        "package_modules": modules,
        "total_licenses": total_licenses,
        "price_amount": config.get("price_amount", 0.0),
        "billing_period": config.get("billing_period", "TAHUNAN"),
        "default_max_members": config.get("default_max_members", 50000),
        "default_levels": config.get("default_levels", ["DPD", "DPC"])
    }


def _extract_package_config(desc: str) -> Dict[str, Any]:
    """Helper to parse JSON config block from description."""
    if "<!--CONFIG:" in desc:
        try:
            start = desc.index("<!--CONFIG:") + len("<!--CONFIG:")
            end = desc.index("-->", start)
            return json.loads(desc[start:end].strip())
        except Exception:
            pass
    return {"price_amount": 0.0, "billing_period": "TAHUNAN", "default_max_members": 50000, "default_levels": ["DPD", "DPC"]}


def _parse_description_and_config(desc: str) -> Tuple[str, Dict[str, Any]]:
    """Splits description from config comment block."""
    if "<!--CONFIG:" in desc:
        parts = desc.split("<!--CONFIG:")
        clean_desc = parts[0].strip()
        config = _extract_package_config(desc)
        return clean_desc, config
    return desc.strip(), {"price_amount": 0.0, "billing_period": "TAHUNAN", "default_max_members": 50000, "default_levels": ["DPD", "DPC"]}
