"""Customer management and lifecycle service."""

from typing import List, Optional, Tuple, Dict, Any
from uuid import UUID
from sqlalchemy.orm import Session
from app.models.customer import Customer
from app.models.installation import Installation
from app.models.license import License
from app.schemas.customer import CustomerCreate, CustomerUpdate
from app.services.audit_service import log_audit_event
from app.services.license_service import compute_license_status


def get_all_customers(db: Session, skip: int = 0, limit: int = 100) -> List[Customer]:
    """Retrieves list of customers ordered by creation date."""
    return db.query(Customer).order_by(Customer.created_at.desc()).offset(skip).limit(limit).all()


def get_customer_by_id(db: Session, customer_id: UUID) -> Optional[Customer]:
    """Finds a customer by primary key."""
    return db.query(Customer).filter(Customer.id == customer_id).first()


def get_customer_by_code(db: Session, code: str) -> Optional[Customer]:
    """Finds a customer by customer code."""
    return db.query(Customer).filter(Customer.customer_code == code).first()


def create_customer(db: Session, data: CustomerCreate, creator_user_id: Optional[UUID] = None) -> Customer:
    """Registers a new customer organization."""
    customer = Customer(
        customer_code=data.customer_code,
        organization_name=data.organization_name,
        contact_person=data.contact_person,
        contact_email=data.contact_email,
        contact_phone=data.contact_phone,
        address=data.address,
        status="ACTIVE",
        notes=data.notes
    )
    db.add(customer)
    db.commit()
    db.refresh(customer)

    log_audit_event(
        db=db,
        action_category="CUSTOMER",
        action_name="CUSTOMER_CREATED",
        user_id=creator_user_id,
        target_resource=f"customer:{customer.customer_code}",
        details={"organization_name": customer.organization_name}
    )
    return customer


def update_customer(
    db: Session,
    customer_id: UUID,
    data: CustomerUpdate,
    user_id: Optional[UUID] = None
) -> Optional[Customer]:
    """Updates attributes of an existing customer organization."""
    customer = get_customer_by_id(db, customer_id)
    if not customer:
        return None

    changes: Dict[str, Any] = {}
    if data.organization_name is not None and data.organization_name != customer.organization_name:
        changes["organization_name"] = {"from": customer.organization_name, "to": data.organization_name}
        customer.organization_name = data.organization_name

    if data.contact_person is not None and data.contact_person != customer.contact_person:
        changes["contact_person"] = {"from": customer.contact_person, "to": data.contact_person}
        customer.contact_person = data.contact_person

    if data.contact_email is not None and data.contact_email != customer.contact_email:
        changes["contact_email"] = {"from": customer.contact_email, "to": data.contact_email}
        customer.contact_email = data.contact_email

    if data.contact_phone is not None:
        customer.contact_phone = data.contact_phone

    if data.address is not None:
        customer.address = data.address

    if data.notes is not None:
        customer.notes = data.notes

    if data.status is not None and data.status != customer.status:
        changes["status"] = {"from": customer.status, "to": data.status}
        customer.status = data.status

    db.commit()
    db.refresh(customer)

    log_audit_event(
        db=db,
        action_category="CUSTOMER",
        action_name="CUSTOMER_UPDATED",
        user_id=user_id,
        target_resource=f"customer:{customer.customer_code}",
        details=changes
    )
    return customer


def set_customer_status(
    db: Session,
    customer_id: UUID,
    new_status: str,
    reason: Optional[str] = None,
    user_id: Optional[UUID] = None
) -> Optional[Customer]:
    """Activates or suspends a customer organization."""
    customer = get_customer_by_id(db, customer_id)
    if not customer:
        return None

    old_status = customer.status
    customer.status = new_status
    db.commit()
    db.refresh(customer)

    log_audit_event(
        db=db,
        action_category="CUSTOMER",
        action_name="CUSTOMER_STATUS_CHANGED",
        user_id=user_id,
        target_resource=f"customer:{customer.customer_code}",
        details={"from": old_status, "to": new_status, "reason": reason or "Perubahan status manual"}
    )
    return customer


def delete_customer(
    db: Session,
    customer_id: UUID,
    user_id: Optional[UUID] = None
) -> Tuple[bool, str]:
    """Deletes a customer organization only after strict relational integrity checks."""
    customer = get_customer_by_id(db, customer_id)
    if not customer:
        return False, "Pelanggan tidak ditemukan."

    licenses_count = db.query(License).filter(License.customer_id == customer_id).count()
    if licenses_count > 0:
        return False, (
            f"Pelanggan '{customer.organization_name}' tidak dapat dihapus karena masih memiliki "
            f"{licenses_count} lisensi komersial terdaftar. Cabut atau bersihkan lisensi terlebih dahulu, "
            f"atau ubah status pelanggan menjadi Nonaktif (Suspended)."
        )

    installations_count = db.query(Installation).filter(Installation.customer_id == customer_id).count()
    if installations_count > 0:
        return False, (
            f"Pelanggan '{customer.organization_name}' tidak dapat dihapus karena masih memiliki "
            f"{installations_count} server instalasi terhubung. Hapus atau pindahkan instalasi server terlebih dahulu."
        )

    code = customer.customer_code
    name = customer.organization_name

    db.delete(customer)
    db.commit()

    log_audit_event(
        db=db,
        action_category="CUSTOMER",
        action_name="CUSTOMER_DELETED",
        user_id=user_id,
        target_resource=f"customer:{code}",
        details={"deleted_organization": name}
    )
    return True, f"Pelanggan '{name}' ({code}) berhasil dihapus secara aman."


def get_customer_installations(db: Session, customer_id: UUID) -> List[Installation]:
    """Retrieves all installations belonging to a specific customer."""
    return db.query(Installation).filter(Installation.customer_id == customer_id).order_by(Installation.created_at.desc()).all()


def get_customer_licenses(db: Session, customer_id: UUID) -> List[Dict[str, Any]]:
    """Retrieves all licenses belonging to a customer with real-time operational status and installations."""
    licenses = db.query(License).filter(License.customer_id == customer_id).order_by(License.created_at.desc()).all()
    results = []
    for lic in licenses:
        bound_insts = [
            f"{link.installation.name} ({link.installation.installation_code})"
            for link in lic.installations
            if link.is_active and link.installation
        ]
        results.append({
            "id": lic.id,
            "license_key": lic.license_key,
            "package_name": lic.package.package_name if lic.package else "Custom",
            "license_type": lic.license_type,
            "status": compute_license_status(lic),
            "valid_from": lic.valid_from,
            "valid_until": lic.valid_until,
            "grace_period_days": lic.grace_period_days,
            "bound_installations": bound_insts
        })
    return results


def get_customer_detail_stats(db: Session, customer_id: UUID) -> Optional[Dict[str, Any]]:
    """Gathers full customer profile along with linked installations and licenses."""
    customer = get_customer_by_id(db, customer_id)
    if not customer:
        return None

    installations = get_customer_installations(db, customer_id)
    licenses = get_customer_licenses(db, customer_id)

    active_inst = sum(1 for inst in installations if inst.status == "ACTIVE")
    active_lic = sum(1 for lic in licenses if lic["status"] == "ACTIVE")

    return {
        "id": customer.id,
        "customer_code": customer.customer_code,
        "organization_name": customer.organization_name,
        "contact_person": customer.contact_person,
        "contact_email": customer.contact_email,
        "contact_phone": customer.contact_phone,
        "address": customer.address,
        "status": customer.status,
        "notes": customer.notes,
        "created_at": customer.created_at,
        "updated_at": customer.updated_at,
        "total_installations": len(installations),
        "active_installations": active_inst,
        "total_licenses": len(licenses),
        "active_licenses": active_lic,
        "installations": installations,
        "licenses": licenses
    }
