"""Unit and integration tests for client-side license activation flow."""

import pytest
from datetime import datetime, timezone, timedelta
from app.models.customer import Customer
from app.models.catalog import LicensePackage
from app.models.license import License, LicenseInstallation
from app.services.license_service import issue_license
from app.schemas.license import LicenseCreate, LicenseCapacityInput


def test_activation_invalid_license_key(client):
    """Test activation fails with a non-existent license key."""
    res = client.post("/api/v1/validations/activate", json={"license_key": "NON-EXISTENT-KEY-999"})
    assert res.status_code == 400
    assert "tidak ditemukan" in res.json()["detail"].lower()


def test_activation_empty_key(client):
    """Test activation fails with an empty or short license key."""
    res = client.post("/api/v1/validations/activate", json={"license_key": "123"})
    assert res.status_code == 422


def test_activation_valid_license(client, db_session):
    """Test successful client-side activation for an issued license."""
    # 1. Setup customer and package
    cust = Customer(
        customer_code="CUST-ACT-01",
        organization_name="Organisasi Uji Aktivasi",
        contact_person="Budi",
        contact_email="budi@uji.id",
        status="ACTIVE",
    )
    pkg = LicensePackage(
        package_code="PKG-ACT-TEST",
        package_name="Paket Uji Aktivasi",
        is_active=True,
    )
    db_session.add(cust)
    db_session.add(pkg)
    db_session.commit()
    db_session.refresh(cust)
    db_session.refresh(pkg)

    # 2. Issue a license (starts as ACTIVE or DRAFT)
    now = datetime.now(timezone.utc)
    lic_create = LicenseCreate(
        customer_id=cust.id,
        package_id=pkg.id,
        license_type="COMMERCIAL",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=365),
        max_installations=2,
        modules=["CORE", "DATA", "SURVEI_GPS"],
        levels=["DPD", "DPC"],
        capacity=LicenseCapacityInput(max_members=25000, max_accounts=100),
    )
    lic = issue_license(db_session, lic_create)

    # 3. Client calls activation endpoint with only the license_key
    res = client.post(
        "/api/v1/validations/activate",
        json={
            "license_key": lic.license_key,
            "instance_name": "Server SIMPATI Klien",
            "server_domain": "klien.simpati555.id",
        },
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["success"] is True
    assert data["license_key"] == lic.license_key
    assert "installation_code" in data and data["installation_code"].startswith("INST-")
    assert "client_id" in data and data["client_id"].startswith("CLT-")
    assert "client_secret" in data and len(data["client_secret"]) > 16
    assert "validation_result" in data
    val = data["validation_result"]
    assert val["validation_status"] == "ACTIVE"
    assert "CORE" in val["allowed_modules"]
    assert "signature" in val

    # 4. Alias endpoint test (/api/v1/licenses/activate)
    alias_res = client.post(
        "/api/v1/licenses/activate",
        json={"license_key": lic.license_key},
    )
    assert alias_res.status_code == 200
    alias_data = alias_res.json()
    assert alias_data["success"] is True
    assert alias_data["installation_code"] == data["installation_code"]
    # Rotated credentials
    assert alias_data["client_id"] != data["client_id"]
