"""Tests for SQLAlchemy models, UUID primary keys, and relationships."""

import uuid
from datetime import datetime, timezone, timedelta
from app.models.base import Base
from app.models.user import LicenseUser
from app.models.customer import Customer
from app.models.installation import Installation
from app.models.catalog import LicensePackage, ModuleRegistry
from app.models.license import License, LicenseCapacity
from app.security.hashing import hash_password


def test_models_metadata_contains_all_entities():
    """Ensures all 24 required entities are properly registered in SQLAlchemy metadata."""
    expected_tables = [
        "license_users", "license_user_sessions", "customers", "installations",
        "installation_credentials", "installation_events", "license_packages",
        "module_registry", "module_dependencies", "package_modules", "licenses",
        "license_installations", "license_modules", "license_capacity", "regions",
        "license_regions", "license_levels", "signing_keys", "revocation_records",
        "api_security_logs", "license_validations", "license_history",
        "license_audit_logs", "system_settings"
    ]
    registered_tables = list(Base.metadata.tables.keys())
    for t in expected_tables:
        assert t in registered_tables, f"Table {t} missing from schema!"


def test_customer_and_installation_creation(db_session):
    """Verifies customer and linked installation creation with UUID."""
    cust_code = f"CUST-TEST-{uuid.uuid4().hex[:6]}"
    cust = Customer(
        customer_code=cust_code,
        organization_name="Organisasi Uji Coba SIMPATI",
        contact_person="Budi Tester",
        contact_email="tester@simpati.org",
        status="ACTIVE"
    )
    db_session.add(cust)
    db_session.commit()
    assert isinstance(cust.id, uuid.UUID)

    inst_code = f"INST-TEST-{uuid.uuid4().hex[:6]}"
    inst = Installation(
        customer_id=cust.id,
        installation_code=inst_code,
        name="Server Uji Coba",
        environment="STAGING",
        status="ACTIVE"
    )
    db_session.add(inst)
    db_session.commit()

    assert inst.customer.id == cust.id
    assert len(cust.installations) == 1
