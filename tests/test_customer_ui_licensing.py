"""Tests for Customer UI Licensing integration: buttons, modals, detail rendering, and license issuance."""

import uuid
from datetime import datetime, timezone, timedelta
from app.models.customer import Customer
from app.models.installation import Installation
from app.models.catalog import LicensePackage, ModuleRegistry
from app.models.license import License, LicenseInstallation
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def test_customers_html_renders_package_license_buttons_and_modal(client, db_session):
    """Verifies that GET /customers renders 'Paket & Lisensi' button and modalIssueLicenseForCustomer."""
    # Login as Superadmin
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})

    cust = Customer(
        customer_code=f"CUST-UI-{uuid.uuid4().hex[:6]}",
        organization_name="Yayasan SIMPATI UI Test",
        contact_person="Rina Melati",
        contact_email="rina@simpati-ui.test",
        status="ACTIVE"
    )
    db_session.add(cust)
    db_session.commit()

    resp = client.get("/customers")
    assert resp.status_code == 200
    html = resp.text

    # 1. Action button 'Paket & Lisensi' must be rendered
    assert "Paket &amp; Lisensi" in html or "Paket & Lisensi" in html
    assert f"openCustomerLicenses('{cust.id}')" in html

    # 2. Detail modal must have tab for Paket & Lisensi
    assert "tabBtnLic" in html
    assert "openIssueLicenseForCurrentCustomer()" in html

    # 3. Dedicated issue license modal for customer must exist in DOM
    assert "modalIssueLicenseForCustomer" in html
    assert "formIssueLicenseForCustomer" in html
    assert "custLicCustomerId" in html
    assert "custLicInstallationId" in html
    assert "custLicPackageId" in html


def test_customer_detail_returns_bound_installations_and_stats(client, db_session):
    """Verifies GET /api/v1/customers/{id}/detail returns bound installations for each license."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})

    # Setup customer, package, installation
    cust = Customer(
        customer_code=f"CUST-BIND-{uuid.uuid4().hex[:6]}",
        organization_name="Organisasi SIMPATI Terikat",
        contact_person="Dewi Sandra",
        contact_email="dewi@simpati-bound.test",
        status="ACTIVE"
    )
    pkg = db_session.query(LicensePackage).first()
    db_session.add(cust)
    db_session.commit()

    inst = Installation(
        customer_id=cust.id,
        installation_code=f"INST-BIND-{uuid.uuid4().hex[:4]}",
        name="Server Utama Terikat",
        environment="PRODUCTION",
        status="ACTIVE"
    )
    db_session.add(inst)
    db_session.commit()

    now = datetime.now(timezone.utc)
    lic = License(
        license_key=f"SMP-LIC-BIND-{uuid.uuid4().hex[:4].upper()}",
        customer_id=cust.id,
        package_id=pkg.id,
        license_type="COMMERCIAL",
        status="ACTIVE",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=365),
        grace_period_days=7
    )
    db_session.add(lic)
    db_session.commit()

    # Bind license to installation
    link = LicenseInstallation(
        license_id=lic.id,
        installation_id=inst.id,
        is_active=True
    )
    db_session.add(link)
    db_session.commit()

    res = client.get(f"/api/v1/customers/{cust.id}/detail")
    assert res.status_code == 200
    data = res.json()

    assert data["total_installations"] == 1
    assert data["total_licenses"] == 1
    assert len(data["licenses"]) == 1

    lic_data = data["licenses"][0]
    assert lic_data["license_key"] == lic.license_key
    assert lic_data["package_name"] == pkg.package_name
    assert "bound_installations" in lic_data
    assert len(lic_data["bound_installations"]) == 1
    assert inst.installation_code in lic_data["bound_installations"][0]


def test_issue_license_flow_for_customer_with_binding_and_signature(client, db_session):
    """Simulates submitting the 'Terbitkan Lisensi' form from customer detail."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")

    cust = Customer(
        customer_code=f"CUST-FLOW-{uuid.uuid4().hex[:6]}",
        organization_name="PT SIMPATI Mandiri Flow",
        contact_person="Bambang Tri",
        contact_email="bambang@mandiri.test",
        status="ACTIVE"
    )
    pkg = db_session.query(LicensePackage).first()
    db_session.add(cust)
    db_session.commit()

    inst = Installation(
        customer_id=cust.id,
        installation_code=f"INST-FLOW-{uuid.uuid4().hex[:4]}",
        name="Server Flow Testing",
        environment="PRODUCTION",
        status="ACTIVE"
    )
    db_session.add(inst)
    db_session.commit()

    now = datetime.now(timezone.utc)
    issue_payload = {
        "customer_id": str(cust.id),
        "package_id": str(pkg.id),
        "installation_id": str(inst.id),
        "license_type": "COMMERCIAL",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=365)).isoformat(),
        "grace_period_days": 7,
        "max_installations": 1,
        "modules": ["CORE", "DATA", "SURVEI_GPS"],
        "levels": ["DPD", "DPC"],
        "capacity": {
            "max_members": 25000,
            "max_accounts": 150,
            "max_concurrent_users": 20,
            "max_storage_mb": 10240,
            "max_gps_points_per_month": 50000
        },
        "notes": "Lisensi khusus diterbitkan dari UI Detail Pelanggan"
    }

    res = client.post(
        "/api/v1/licenses",
        json=issue_payload,
        headers={"X-CSRF-Token": csrf_token} if csrf_token else {}
    )
    assert res.status_code == 201
    lic_res = res.json()

    assert lic_res["license_key"].startswith("SMP-LIC-")
    assert lic_res["signature"] is not None

    # Verify that the license is bound to the installation in database
    binding = (
        db_session.query(LicenseInstallation)
        .filter(
            LicenseInstallation.license_id == uuid.UUID(lic_res["id"]),
            LicenseInstallation.installation_id == inst.id,
            LicenseInstallation.is_active == True
        )
        .first()
    )
    assert binding is not None

    # Verify that customer detail now immediately reflects the issued license
    detail_res = client.get(f"/api/v1/customers/{cust.id}/detail")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()

    assert detail_data["total_licenses"] == 1
    assert detail_data["licenses"][0]["license_key"] == lic_res["license_key"]
    assert detail_data["licenses"][0]["status"] == "ACTIVE"
    assert inst.installation_code in detail_data["licenses"][0]["bound_installations"][0]

def test_customers_html_structure_and_no_duplicate_modals(client, db_session):
    """Verifies that customers.html has clean title, clean header, and zero duplicate modal IDs."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    res = client.get("/customers")
    assert res.status_code == 200
    html = res.text

    import re
    titles = re.findall(r"<title>(.*?)</title>", html, re.DOTALL)
    assert len(titles) == 1
    assert "modalIssueLicenseForCustomer" not in titles[0]
    assert "formIssueLicenseForCustomer" not in titles[0]
    assert "Pelanggan - SIMPATI License Manager" in titles[0]

    # Ensure modalIssueLicenseForCustomer only exists once as an element ID in body
    modal_ids = [m for m in html.split() if 'id="modalIssueLicenseForCustomer"' in m or "id='modalIssueLicenseForCustomer'" in m]
    assert len(modal_ids) == 1, f"Expected 1 modalIssueLicenseForCustomer ID, got {len(modal_ids)}"

    # Ensure formIssueLicenseForCustomer only exists once
    form_ids = [f for f in html.split() if 'id="formIssueLicenseForCustomer"' in f or "id='formIssueLicenseForCustomer'" in f]
    assert len(form_ids) == 1, f"Expected 1 formIssueLicenseForCustomer ID, got {len(form_ids)}"

    # Ensure modal has z-index: 1100
    assert 'z-index: 1100' in html


def test_package_selection_endpoint_provides_required_fields(client, db_session):
    """Verifies that GET /api/v1/packages/{id}/detail returns modules and defaults for onCustLicensePackageChange."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    pkg = db_session.query(LicensePackage).first()
    assert pkg is not None

    res = client.get(f"/api/v1/packages/{pkg.id}/detail")
    assert res.status_code == 200
    data = res.json()

    assert "modules" in data
    assert isinstance(data["modules"], list)
    assert "default_levels" in data
    assert "default_max_members" in data
