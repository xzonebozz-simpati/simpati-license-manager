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


def test_delete_customer_cascades_active_license_and_installation_data(client, db_session):
    """Deleting a customer permanently removes active licenses and linked installation data."""
    from app.models.license import LicenseInstallation, LicenseModule, LicenseCapacity
    from app.models.installation import InstallationCredential, InstallationEvent
    from app.models.operations import LicenseValidation, LicenseHistory, LicenseAuditLog
    from app.models.security import RevocationRecord

    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")
    cust = Customer(
        customer_code=f"CUST-CASCADE-{uuid.uuid4().hex[:6]}",
        organization_name=f"Cascade Org {uuid.uuid4().hex[:5]}",
        contact_person="Contact", contact_email="cascade@test.id"
    )
    db_session.add(cust)
    db_session.commit()

    pkg = db_session.query(LicensePackage).first()
    now = datetime.now(timezone.utc)
    inst = Installation(customer_id=cust.id, installation_code=f"INST-CAS-{uuid.uuid4().hex[:5]}",
                       name="Cascade Server", status="ACTIVE")
    lic = License(license_key=f"LIC-CAS-{uuid.uuid4().hex[:8].upper()}", customer_id=cust.id,
                  package_id=pkg.id, valid_from=now, valid_until=now + timedelta(days=30), status="ACTIVE")
    db_session.add_all([inst, lic])
    db_session.flush()
    from app.models.installation import InstallationCredential, InstallationEvent
    from app.models.license import LicenseInstallation, LicenseModule, LicenseCapacity
    db_session.add(InstallationCredential(installation_id=inst.id, client_id=f"CLT-{uuid.uuid4().hex[:12]}",
                                           client_secret_hash="not-a-real-secret-hash"))
    db_session.add(InstallationEvent(installation_id=inst.id, event_type="TEST"))
    db_session.add(LicenseInstallation(license_id=lic.id, installation_id=inst.id))
    db_session.add(LicenseModule(license_id=lic.id, module_code="CORE"))
    db_session.add(LicenseCapacity(license_id=lic.id))
    db_session.add(LicenseValidation(
        license_id=lic.id, installation_id=inst.id, validation_token=f"VAL-{uuid.uuid4().hex}",
        validation_status="VALID", next_validation_due=now + timedelta(hours=1)
    ))
    db_session.add(LicenseHistory(license_id=lic.id, action="TEST_CREATED"))
    db_session.add(RevocationRecord(entity_type="LICENSE", entity_id=lic.id,
                                    revocation_code="TEST", reason="test cleanup"))
    db_session.commit()
    customer_id, license_id, installation_id = cust.id, lic.id, inst.id

    res = client.request("DELETE", f"/api/v1/customers/{customer_id}", json={"confirmation": cust.organization_name},
                        headers={"X-CSRF-Token": csrf_token})
    assert res.status_code == 200, res.text
    assert "berhasil dihapus permanen" in res.json()["message"]
    assert db_session.query(Customer).filter(Customer.id == customer_id).first() is None
    assert db_session.query(License).filter(License.id == license_id).first() is None
    assert db_session.query(Installation).filter(Installation.id == installation_id).first() is None
    assert db_session.query(InstallationCredential).filter(InstallationCredential.installation_id == installation_id).count() == 0
    assert db_session.query(InstallationEvent).filter(InstallationEvent.installation_id == installation_id).count() == 0
    assert db_session.query(LicenseInstallation).filter(LicenseInstallation.license_id == license_id).count() == 0
    assert db_session.query(LicenseModule).filter(LicenseModule.license_id == license_id).count() == 0
    assert db_session.query(LicenseCapacity).filter(LicenseCapacity.license_id == license_id).count() == 0
    assert db_session.query(LicenseValidation).filter(LicenseValidation.license_id == license_id).count() == 0
    assert db_session.query(LicenseHistory).filter(LicenseHistory.license_id == license_id).count() == 0
    assert db_session.query(RevocationRecord).filter(RevocationRecord.entity_id.in_([license_id, installation_id])).count() == 0
    assert db_session.query(LicenseAuditLog).filter(
        LicenseAuditLog.action_name == "CUSTOMER_PERMANENTLY_DELETED",
        LicenseAuditLog.target_resource.like("customer:%")
    ).count() >= 1


def test_delete_customer_requires_exact_name_confirmation(client, db_session):
    client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "SuperAdmin@2026!"})
    csrf_token = client.cookies.get("simpati_csrf_token")
    cust = Customer(customer_code=f"CUST-CONF-{uuid.uuid4().hex[:6]}", organization_name="Confirmation Org",
                    contact_person="Contact", contact_email="confirm@test.id")
    db_session.add(cust)
    db_session.commit()
    res = client.request("DELETE", f"/api/v1/customers/{cust.id}", json={"confirmation": "Wrong Name"},
                        headers={"X-CSRF-Token": csrf_token})
    assert res.status_code == 400
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
    res = client.request(
        "DELETE", f"/api/v1/customers/{cust_id}",
        json={"confirmation": "Clean Customer"},
        headers={"X-CSRF-Token": csrf_token}
    )
    assert res.status_code == 200
    assert "berhasil dihapus" in res.json()["message"]

    # Verify customer is deleted
    assert db_session.query(Customer).filter(Customer.id == cust_id).first() is None
