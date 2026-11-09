"""Tests for services, business rules, grace period, and endpoints."""

from datetime import datetime, timezone, timedelta
from app.models.customer import Customer
from app.models.installation import Installation
from app.models.catalog import LicensePackage
from app.models.license import License
from app.schemas.customer import CustomerCreate
from app.schemas.license import LicenseCreate, LicenseCapacityInput
from app.services.customer_service import create_customer, get_all_customers
from app.services.license_service import issue_license, compute_license_status
from app.services.validation_service import validate_installation_license


def test_customer_service_flow(db_session):
    """Tests creating and querying customer organizations."""
    payload = CustomerCreate(
        customer_code="CUST-SERVICE-TEST",
        organization_name="Yayasan SIMPATI Makmur",
        contact_person="Ahmad Fauzi",
        contact_email="ahmad@simpatimakmur.id",
        contact_phone="+628111222333"
    )
    cust = create_customer(db=db_session, data=payload)
    assert cust.customer_code == "CUST-SERVICE-TEST"
    assert cust.status == "ACTIVE"

    customers = get_all_customers(db=db_session)
    assert any(c.customer_code == "CUST-SERVICE-TEST" for c in customers)


def test_license_status_computation(db_session):
    """Tests compute_license_status for ACTIVE, GRACE_PERIOD, and RESTRICTED."""
    now = datetime.now(timezone.utc)
    cust = Customer(
        customer_code="CUST-STATUS-TEST",
        organization_name="Status Org",
        contact_person="Person",
        contact_email="p@status.test"
    )
    pkg = LicensePackage(package_code="PKG-ST", package_name="Pkg ST")
    db_session.add_all([cust, pkg])
    db_session.commit()

    # 1. Active License
    lic_active = License(
        license_key="LIC-ACTIVE",
        customer_id=cust.id,
        package_id=pkg.id,
        status="ACTIVE",
        valid_from=now - timedelta(days=10),
        valid_until=now + timedelta(days=10),
        grace_period_days=7
    )
    assert compute_license_status(lic_active) == "ACTIVE"

    # 2. In Grace Period
    lic_grace = License(
        license_key="LIC-GRACE",
        customer_id=cust.id,
        package_id=pkg.id,
        status="ACTIVE",
        valid_from=now - timedelta(days=30),
        valid_until=now - timedelta(days=2),  # Expired 2 days ago
        grace_period_days=7                   # Within 7 days grace
    )
    assert compute_license_status(lic_grace) == "GRACE_PERIOD"

    # 3. Restricted Mode (Exceeded grace period)
    lic_restricted = License(
        license_key="LIC-RESTRICTED",
        customer_id=cust.id,
        package_id=pkg.id,
        status="ACTIVE",
        valid_from=now - timedelta(days=60),
        valid_until=now - timedelta(days=20), # Expired 20 days ago
        grace_period_days=7                   # 20 > 7 days
    )
    assert compute_license_status(lic_restricted) == "RESTRICTED"


def test_license_issuance_and_validation(db_session):
    """Tests issuing a license with snapshot entitlements and running online validation."""
    now = datetime.now(timezone.utc)
    cust = Customer(
        customer_code="CUST-VAL-TEST",
        organization_name="Validation Customer",
        contact_person="Val Person",
        contact_email="val@customer.id"
    )
    pkg = LicensePackage(package_code="PKG-VAL", package_name="Pkg Val")
    db_session.add_all([cust, pkg])
    db_session.commit()

    inst = Installation(
        customer_id=cust.id,
        installation_code="INST-VAL-01",
        name="Validation Server",
        environment="PRODUCTION",
        status="ACTIVE"
    )
    db_session.add(inst)
    db_session.commit()

    lic_data = LicenseCreate(
        customer_id=cust.id,
        package_id=pkg.id,
        license_type="COMMERCIAL",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
        grace_period_days=7,
        max_installations=1,
        modules=["CORE", "DATA", "SURVEI_GPS"],
        levels=["DPD", "DPC"],
        capacity=LicenseCapacityInput(max_members=25000, max_accounts=100)
    )
    from app.models.license import LicenseInstallation
    license_obj = issue_license(db=db_session, data=lic_data)
    assert license_obj.license_key.startswith("SMP-LIC-")

    # Create required LicenseInstallation binding before calling validate_installation_license.
    # The new validation_service requires an explicit binding record (license_installations table).
    binding = LicenseInstallation(
        license_id=license_obj.id,
        installation_id=inst.id,
        is_active=True
    )
    db_session.add(binding)
    db_session.commit()

    # Validate online
    val_result = validate_installation_license(
        db=db_session,
        license_key=license_obj.license_key,
        installation_code="INST-VAL-01",
        request_ip="127.0.0.1"
    )
    assert val_result["validation_status"] == "ACTIVE"
    assert val_result["is_restricted_mode"] is False
    assert "CORE" in val_result["allowed_modules"]
    assert val_result["capacity"]["max_members"] == 25000


def test_web_routes_render_html(client):
    """Tests that HTML views render without errors for authenticated users."""
    # Authenticate first
    client.post(
        "/api/v1/auth/login",
        json={"username": "superadmin", "password": "SuperAdmin@2026!"}
    )
    routes = [
        "/",
        "/customers",
        "/installations",
        "/packages",
        "/modules",
        "/licenses",
        "/validations",
        "/history",
        "/audit",
        "/settings"
    ]
    for route in routes:
        resp = client.get(route)
        assert resp.status_code == 200
        assert "SIMPATI" in resp.text
