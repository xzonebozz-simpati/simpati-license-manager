"""Comprehensive tests for customer management, detail with relations, updates, status toggle, and safe deletion."""

import uuid
from datetime import datetime, timezone, timedelta
from app.models.customer import Customer
from app.models.installation import Installation
from app.models.catalog import LicensePackage
from app.models.license import License
from app.services.customer_service import create_customer, delete_customer
from app.schemas.customer import CustomerCreate


def test_customer_detail_with_stats_and_sublists(client, db_session):
    """Verifies that GET /api/v1/customers/{id}/detail returns complete profile, counts, and lists."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")

    # 1. Setup Customer
    cust = Customer(
        customer_code=f"CUST-DTL-{uuid.uuid4().hex[:6]}",
        organization_name="DPD SIMPATI Bali",
        contact_person="Wayan Sudirta",
        contact_email="wayan@simpatibali.org",
        contact_phone="+6281333444555",
        address="Denpasar, Bali",
        status="ACTIVE"
    )
    db_session.add(cust)
    db_session.commit()

    # 2. Setup Linked Installation
    inst = Installation(
        customer_id=cust.id,
        installation_code=f"INST-BALI-{uuid.uuid4().hex[:4]}",
        name="Server Utama Bali",
        server_domain="bali.simpati555.id",
        environment="PRODUCTION",
        status="ACTIVE"
    )
    # 3. Setup Linked License
    pkg = db_session.query(LicensePackage).first()
    now = datetime.now(timezone.utc)
    lic = License(
        license_key=f"SMP-LIC-BALI-{uuid.uuid4().hex[:4].upper()}",
        customer_id=cust.id,
        package_id=pkg.id,
        license_type="COMMERCIAL",
        status="ACTIVE",
        valid_from=now - timedelta(days=5),
        valid_until=now + timedelta(days=360),
        grace_period_days=7
    )
    db_session.add_all([inst, lic])
    db_session.commit()

    # Query Detail
    res = client.get(f"/api/v1/customers/{cust.id}/detail")
    assert res.status_code == 200
    data = res.json()
    assert data["customer_code"] == cust.customer_code
    assert data["organization_name"] == "DPD SIMPATI Bali"
    assert data["total_installations"] == 1
    assert data["active_installations"] == 1
    assert data["total_licenses"] == 1
    assert data["active_licenses"] == 1
    assert len(data["installations"]) == 1
    assert data["installations"][0]["installation_code"] == inst.installation_code
    assert len(data["licenses"]) == 1
    assert data["licenses"][0]["license_key"] == lic.license_key

    # Query installations endpoint specifically
    inst_res = client.get(f"/api/v1/customers/{cust.id}/installations")
    assert inst_res.status_code == 200
    assert len(inst_res.json()) == 1

    # Query licenses endpoint specifically
    lic_res = client.get(f"/api/v1/customers/{cust.id}/licenses")
    assert lic_res.status_code == 200
    assert len(lic_res.json()) == 1


def test_update_customer_data(client, db_session):
    """Verifies updating customer information via PUT /api/v1/customers/{id}."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")

    cust = Customer(
        customer_code=f"CUST-UPD-{uuid.uuid4().hex[:6]}",
        organization_name="Nama Awal",
        contact_person="Person Awal",
        contact_email="awal@test.id",
        status="ACTIVE"
    )
    db_session.add(cust)
    db_session.commit()

    update_payload = {
        "organization_name": "Nama Organisasi Baru",
        "contact_person": "Nama Kontak Baru",
        "contact_email": "baru@test.id",
        "contact_phone": "+628999888777",
        "address": "Jl. Baru No. 123",
        "notes": "Diperbarui via test"
    }

    res = client.put(
        f"/api/v1/customers/{cust.id}",
        json=update_payload,
        headers={"X-CSRF-Token": csrf_token}
    )
    assert res.status_code == 200
    updated = res.json()
    assert updated["organization_name"] == "Nama Organisasi Baru"
    assert updated["contact_person"] == "Nama Kontak Baru"
    assert updated["contact_email"] == "baru@test.id"
    assert updated["contact_phone"] == "+628999888777"


def test_toggle_customer_status(client, db_session):
    """Verifies activating and suspending a customer via PATCH /api/v1/customers/{id}/status."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")

    cust = Customer(
        customer_code=f"CUST-TOGGLE-{uuid.uuid4().hex[:6]}",
        organization_name="Status Toggle Org",
        contact_person="Person",
        contact_email="toggle@test.id",
        status="ACTIVE"
    )
    db_session.add(cust)
    db_session.commit()

    # 1. Suspend customer
    res1 = client.patch(
        f"/api/v1/customers/{cust.id}/status",
        json={"status": "SUSPENDED", "reason": "Tunggakan perpanjangan"},
        headers={"X-CSRF-Token": csrf_token}
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "SUSPENDED"

    # 2. Re-activate customer
    res2 = client.patch(
        f"/api/v1/customers/{cust.id}/status",
        json={"status": "ACTIVE", "reason": "Administrasi selesai"},
        headers={"X-CSRF-Token": csrf_token}
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "ACTIVE"


def test_safe_delete_customer_rejected_if_has_license(client, db_session):
    """Verifies that deleting a customer with active or historical licenses is strictly rejected."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")

    cust = Customer(
        customer_code=f"CUST-DEL-LIC-{uuid.uuid4().hex[:6]}",
        organization_name="Customer With License",
        contact_person="Contact",
        contact_email="custlic@test.id"
    )
    db_session.add(cust)
    db_session.commit()

    pkg = db_session.query(LicensePackage).first()
    now = datetime.now(timezone.utc)
    lic = License(
        license_key=f"LIC-GUARD-{uuid.uuid4().hex[:4].upper()}",
        customer_id=cust.id,
        package_id=pkg.id,
        valid_from=now,
        valid_until=now + timedelta(days=30),
        status="ACTIVE"
    )
    db_session.add(lic)
    db_session.commit()

    # Attempt deletion
    res = client.delete(
        f"/api/v1/customers/{cust.id}",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert res.status_code == 400
    assert "tidak dapat dihapus karena masih memiliki" in res.json()["detail"]
    assert "lisensi komersial" in res.json()["detail"]

    # Verify customer still exists
    assert db_session.query(Customer).filter(Customer.id == cust.id).first() is not None


def test_safe_delete_customer_rejected_if_has_installation(client, db_session):
    """Verifies that deleting a customer with linked server installation is strictly rejected."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")

    cust = Customer(
        customer_code=f"CUST-DEL-INST-{uuid.uuid4().hex[:6]}",
        organization_name="Customer With Server",
        contact_person="Contact",
        contact_email="custinst@test.id"
    )
    db_session.add(cust)
    db_session.commit()

    inst = Installation(
        customer_id=cust.id,
        installation_code=f"INST-GUARD-{uuid.uuid4().hex[:4]}",
        name="Server Guard Test",
        status="ACTIVE"
    )
    db_session.add(inst)
    db_session.commit()

    # Attempt deletion
    res = client.delete(
        f"/api/v1/customers/{cust.id}",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert res.status_code == 400
    assert "server instalasi" in res.json()["detail"]

    # Verify customer still exists
    assert db_session.query(Customer).filter(Customer.id == cust.id).first() is not None


def test_safe_delete_customer_clean_success(client, db_session):
    """Verifies that deleting a customer with NO relations succeeds cleanly."""
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")

    cust = Customer(
        customer_code=f"CUST-CLEAN-{uuid.uuid4().hex[:6]}",
        organization_name="Clean Customer",
        contact_person="Clean Contact",
        contact_email="clean@test.id"
    )
    db_session.add(cust)
    db_session.commit()
    cust_id = cust.id

    # Deletion must succeed
    res = client.delete(
        f"/api/v1/customers/{cust_id}",
        headers={"X-CSRF-Token": csrf_token}
    )
    assert res.status_code == 200
    assert "berhasil dihapus" in res.json()["message"]

    # Verify customer is deleted
    assert db_session.query(Customer).filter(Customer.id == cust_id).first() is None
