"""Unit and integration tests for SIMPATI Package & License Module (Iteration 5)."""

import json
from datetime import datetime, timezone, timedelta
from uuid import uuid4, UUID
import pytest
from fastapi.testclient import TestClient

from app.models.customer import Customer
from app.models.installation import Installation
from app.models.catalog import LicensePackage, ModuleRegistry
from app.models.license import License
from app.models.security import RevocationRecord
from app.models.user import LicenseUser
from app.security.hashing import hash_password
from app.services.auth_service import authenticate_user
from app.services.license_service import get_root_public_key
from app.security.crypto import verify_signature


@pytest.fixture
def auth_headers(db_session):
    """Provides authorization cookie and CSRF headers for Superadmin requests."""
    admin = db_session.query(LicenseUser).filter(LicenseUser.username == "testadmin").first()
    if not admin:
        admin = LicenseUser(
            username="testadmin",
            email="testadmin@simpati.test",
            full_name="Test Superadmin",
            password_hash=hash_password("TestSecret@2026!"),
            role="SUPERADMIN",
            is_active=True
        )
        db_session.add(admin)
        db_session.commit()

    _, token, _ = authenticate_user(db_session, "testadmin", "TestSecret@2026!")
    return {
        "cookie": f"simpati_session={token}; simpati_csrf_token=test_csrf_token_val",
        "X-CSRF-Token": "test_csrf_token_val"
    }


@pytest.fixture
def sample_customer_and_inst(db_session):
    """Creates a fresh customer organization and linked server installation."""
    suffix = uuid4().hex[:6].upper()
    cust = Customer(
        customer_code=f"CUST-LIC-{suffix}",
        organization_name=f"Sinode Wilayah {suffix}",
        contact_person="Ketua Majelis",
        contact_email=f"sinode.{suffix.lower()}@test.org",
        status="ACTIVE"
    )
    db_session.add(cust)
    db_session.flush()

    inst = Installation(
        customer_id=cust.id,
        installation_code=f"INST-SRV-{suffix}",
        name=f"Server Pusat {suffix}",
        environment="PRODUCTION",
        status="ACTIVE"
    )
    db_session.add(inst)
    db_session.commit()
    db_session.refresh(cust)
    db_session.refresh(inst)
    return cust, inst


# ---------------------------------------------------------------------------
# Package Catalog Tests
# ---------------------------------------------------------------------------

def test_package_crud_lifecycle(client: TestClient, auth_headers):
    """Tests creating, fetching, updating, and toggling status of a commercial package."""
    pkg_code = f"PKG-TEST-{uuid4().hex[:4].upper()}"
    payload = {
        "package_code": pkg_code,
        "package_name": "Paket Wilayah Khusus",
        "default_tier": "PROFESSIONAL",
        "billing_period": "TAHUNAN",
        "default_max_members": 75000,
        "description": "Paket penawaran dengan modul lengkap wilayah.",
        "modules": ["CORE", "DATA", "SURVEI_GPS"],
        "levels": ["DPD", "DPC", "DPS"]
    }
    # 1. Create Package
    create_resp = client.post(
        "/api/v1/packages",
        json=payload,
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["package_code"] == pkg_code
    assert created_data["package_name"] == "Paket Wilayah Khusus"
    pkg_id = created_data["id"]

    # 2. Get Package Detail
    det_resp = client.get(
        f"/api/v1/packages/{pkg_id}/detail",
        headers={"Cookie": auth_headers["cookie"]}
    )
    assert det_resp.status_code == 200
    det_data = det_resp.json()
    assert det_data["default_max_members"] == 75000
    assert "SURVEI_GPS" in det_data["modules"]
    assert "DPS" in det_data["default_levels"]

    # 3. Update Package
    upd_resp = client.put(
        f"/api/v1/packages/{pkg_id}",
        json={
            "package_name": "Paket Wilayah Khusus Diperbarui",
            "default_max_members": 100000,
            "modules": ["CORE", "DATA", "SURVEI_GPS", "REPORT_ADV"]
        },
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert upd_resp.status_code == 200
    assert upd_resp.json()["package_name"] == "Paket Wilayah Khusus Diperbarui"

    # 4. Toggle Status (Deactivate & Activate)
    toggle_off = client.patch(
        f"/api/v1/packages/{pkg_id}/status",
        json={"is_active": False},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert toggle_off.status_code == 200
    assert toggle_off.json()["is_active"] is False

    toggle_on = client.patch(
        f"/api/v1/packages/{pkg_id}/status",
        json={"is_active": True},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert toggle_on.status_code == 200
    assert toggle_on.json()["is_active"] is True


def test_package_duplicate_code_fails(client: TestClient, auth_headers):
    """Tests that package codes must be unique."""
    pkg_code = f"PKG-UNIQ-{uuid4().hex[:4].upper()}"
    client.post(
        "/api/v1/packages",
        json={"package_code": pkg_code, "package_name": "Paket Satu"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    dup_resp = client.post(
        "/api/v1/packages",
        json={"package_code": pkg_code, "package_name": "Paket Dua"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert dup_resp.status_code == 400
    assert "sudah terdaftar" in dup_resp.json()["detail"]


# ---------------------------------------------------------------------------
# Commercial License Tests
# ---------------------------------------------------------------------------

def test_issue_license_with_ed25519_signature(client: TestClient, db_session, auth_headers, sample_customer_and_inst):
    """Tests issuing a commercial license and verifying digital cryptographic signature with Ed25519."""
    cust, inst = sample_customer_and_inst
    pkg = db_session.query(LicensePackage).first()
    assert pkg is not None

    now = datetime.now(timezone.utc)
    from_date = now.strftime("%Y-%m-%d")
    until_date = (now + timedelta(days=365)).strftime("%Y-%m-%d")

    payload = {
        "customer_id": str(cust.id),
        "package_id": str(pkg.id),
        "installation_id": str(inst.id),
        "license_type": "COMMERCIAL",
        "valid_from": f"{from_date}T00:00:00Z",
        "valid_until": f"{until_date}T23:59:59Z",
        "grace_period_days": 7,
        "max_installations": 2,
        "modules": ["CORE", "DATA", "SURVEI_GPS", "UMKM"],
        "levels": ["DPD", "DPC", "DPS"],
        "capacity": {
            "max_members": 60000,
            "max_accounts": 250,
            "max_concurrent_users": 30,
            "max_storage_mb": 25000,
            "max_gps_points_per_month": 120000
        },
        "notes": "Kontrak Lisensi Resmi Gereja 2026"
    }

    resp = client.post(
        "/api/v1/licenses",
        json=payload,
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert resp.status_code == 201
    lic_data = resp.json()
    assert "license_key" in lic_data
    assert lic_data["license_key"].startswith("SMP-LIC-")
    assert lic_data["signature"] is not None
    assert len(lic_data["signature"]) > 40
    lic_id = lic_data["license_id"]

    # Verify detail and cryptographic signature validity
    det_resp = client.get(
        f"/api/v1/licenses/{lic_id}/detail",
        headers={"Cookie": auth_headers["cookie"]}
    )
    assert det_resp.status_code == 200
    det = det_resp.json()
    assert det["signature_valid"] is True
    assert det["customer_code"] == cust.customer_code
    assert len(det["installations"]) == 1
    assert det["installations"][0]["installation_code"] == inst.installation_code
    assert "SURVEI_GPS" in det["modules"]
    assert det["capacity"]["max_members"] == 60000


def test_extend_license_and_re_signing(client: TestClient, db_session, auth_headers, sample_customer_and_inst):
    """Tests extending license validity and verifying that a new valid Ed25519 signature is produced."""
    cust, _ = sample_customer_and_inst
    pkg = db_session.query(LicensePackage).first()

    now = datetime.now(timezone.utc)
    until_1 = now + timedelta(days=180)
    until_2 = now + timedelta(days=540)

    # Issue initial license
    payload = {
        "customer_id": str(cust.id),
        "package_id": str(pkg.id),
        "license_type": "COMMERCIAL",
        "valid_from": now.isoformat(),
        "valid_until": until_1.isoformat(),
        "grace_period_days": 7,
        "max_installations": 1,
        "modules": ["CORE", "DATA"]
    }
    create_resp = client.post(
        "/api/v1/licenses",
        json=payload,
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    lic_id = create_resp.json()["license_id"]
    old_sig = create_resp.json()["signature"]

    # Extend license
    ext_resp = client.post(
        f"/api/v1/licenses/{lic_id}/extend",
        json={
            "valid_until": until_2.isoformat(),
            "reason": "Perpanjangan kontrak kemitraan 1 tahun tambahan"
        },
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert ext_resp.status_code == 200
    ext_data = ext_resp.json()
    assert ext_data["signature"] != old_sig

    # Verify signature validity on extended license
    det_resp = client.get(
        f"/api/v1/licenses/{lic_id}/detail",
        headers={"Cookie": auth_headers["cookie"]}
    )
    assert det_resp.status_code == 200
    det = det_resp.json()
    assert det["signature_valid"] is True
    # History must record extension
    actions = [h["action"] for h in det["history"]]
    assert "EXTENDED" in actions


def test_license_status_lifecycle_and_crl_revocation(client: TestClient, db_session, auth_headers, sample_customer_and_inst):
    """Tests suspending, reactivating, and revoking a license, verifying CRL entry creation."""
    cust, _ = sample_customer_and_inst
    pkg = db_session.query(LicensePackage).first()
    now = datetime.now(timezone.utc)

    create_resp = client.post(
        "/api/v1/licenses",
        json={
            "customer_id": str(cust.id),
            "package_id": str(pkg.id),
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=365)).isoformat(),
            "modules": ["CORE"]
        },
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    lic_id = create_resp.json()["license_id"]

    # 1. Suspend
    susp_resp = client.patch(
        f"/api/v1/licenses/{lic_id}/status",
        json={"status": "SUSPENDED", "reason": "Pemeriksaan administrasi berkala"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert susp_resp.status_code == 200
    assert susp_resp.json()["status"] == "SUSPENDED"

    # 2. Reactivate
    react_resp = client.patch(
        f"/api/v1/licenses/{lic_id}/status",
        json={"status": "ACTIVE", "reason": "Administrasi telah lengkap dan terverifikasi"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert react_resp.status_code == 200
    assert react_resp.json()["status"] == "ACTIVE"

    # 3. Revoke (Permanent termination)
    rev_resp = client.patch(
        f"/api/v1/licenses/{lic_id}/status",
        json={"status": "REVOKED", "reason": "Pemutusan perjanjian lisensi komersial"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert rev_resp.status_code == 200
    assert rev_resp.json()["status"] == "REVOKED"

    # Verify CRL entry in revocation_records table
    from uuid import UUID
    crl_record = db_session.query(RevocationRecord).filter(
        RevocationRecord.entity_id == UUID(lic_id),
        RevocationRecord.entity_type == "LICENSE"
    ).first()
    assert crl_record is not None
    assert "Pemutusan perjanjian" in crl_record.reason


def test_snapshot_immutability_on_package_change(client: TestClient, db_session, auth_headers, sample_customer_and_inst):
    """
    CRITICAL BUSINESS RULE:
    Changing the catalog package must NEVER alter or mutate the entitlements of an already-issued license.
    """
    cust, _ = sample_customer_and_inst
    # 1. Create a dedicated package with [CORE, DATA]
    pkg_code = f"PKG-IMMUT-{uuid4().hex[:4].upper()}"
    p_resp = client.post(
        "/api/v1/packages",
        json={
            "package_code": pkg_code,
            "package_name": "Paket Snapshot Test",
            "modules": ["CORE", "DATA"]
        },
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    pkg_id = p_resp.json()["id"]

    # 2. Issue license with snapshot entitlements
    now = datetime.now(timezone.utc)
    lic_resp = client.post(
        "/api/v1/licenses",
        json={
            "customer_id": str(cust.id),
            "package_id": pkg_id,
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=365)).isoformat(),
            "modules": ["CORE", "DATA"]
        },
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    lic_id = lic_resp.json()["license_id"]

    # 3. Now modify the package catalog: remove DATA and add SURVEI_GPS, UMKM
    client.put(
        f"/api/v1/packages/{pkg_id}",
        json={
            "package_name": "Paket Snapshot Telah Diubah",
            "modules": ["CORE", "SURVEI_GPS", "UMKM"]
        },
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )

    # 4. Check the license details: it MUST retain the original snapshot modules [CORE, DATA]
    det_resp = client.get(
        f"/api/v1/licenses/{lic_id}/detail",
        headers={"Cookie": auth_headers["cookie"]}
    )
    det = det_resp.json()
    assert "DATA" in det["modules"]
    assert "SURVEI_GPS" not in det["modules"]
    assert "UMKM" not in det["modules"]
    assert det["signature_valid"] is True


def test_edit_license_validity_shorten_and_resign(client: TestClient, db_session, auth_headers, sample_customer_and_inst):
    """Koreksi jangka waktu salah input: bisa dipersingkat, snapshot ditandatangani ulang, riwayat tercatat."""
    cust, _ = sample_customer_and_inst
    pkg = db_session.query(LicensePackage).first()
    now = datetime.now(timezone.utc)
    hdrs = {"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}

    # Salah input: 5 tahun, seharusnya 6 bulan
    create_resp = client.post(
        "/api/v1/licenses",
        json={
            "customer_id": str(cust.id),
            "package_id": str(pkg.id),
            "valid_from": now.isoformat(),
            "valid_until": (now + timedelta(days=365 * 5)).isoformat(),
            "modules": ["CORE", "DATA"],
        },
        headers=hdrs,
    )
    assert create_resp.status_code == 201
    lic_id = create_resp.json()["license_id"]
    old_sig = create_resp.json()["signature"]

    new_until = now + timedelta(days=180)
    resp = client.patch(
        f"/api/v1/licenses/{lic_id}/validity",
        json={
            "valid_from": now.isoformat(),
            "valid_until": new_until.isoformat(),
            "grace_period_days": 14,
            "reason": "Salah input durasi saat penerbitan",
        },
        headers=hdrs,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["signature"] != old_sig
    assert resp.json()["grace_period_days"] == 14

    det = client.get(f"/api/v1/licenses/{lic_id}/detail", headers={"Cookie": auth_headers["cookie"]}).json()
    assert det["signature_valid"] is True
    assert det["grace_period_days"] == 14
    assert json.loads(det["snapshot_entitlements"])["valid_until"] == new_until.astimezone(timezone.utc).isoformat()
    assert "VALIDITY_EDITED" in [h["action"] for h in det["history"]]

    # Tanggal tidak valid & tanpa perubahan ditolak
    bad = client.patch(
        f"/api/v1/licenses/{lic_id}/validity",
        json={"valid_from": now.isoformat(), "valid_until": (now - timedelta(days=1)).isoformat(), "reason": "tes"},
        headers=hdrs,
    )
    assert bad.status_code == 400
    same = client.patch(
        f"/api/v1/licenses/{lic_id}/validity",
        json={"valid_from": now.isoformat(), "valid_until": new_until.isoformat(), "grace_period_days": 14, "reason": "tes"},
        headers=hdrs,
    )
    assert same.status_code == 400


def test_edit_license_validity_revives_expired(client: TestClient, db_session, auth_headers, sample_customer_and_inst):
    """Lisensi EXPIRED yang periodenya dikoreksi ke masa depan kembali aktif."""
    cust, _ = sample_customer_and_inst
    pkg = db_session.query(LicensePackage).first()
    now = datetime.now(timezone.utc)
    hdrs = {"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}

    create_resp = client.post(
        "/api/v1/licenses",
        json={
            "customer_id": str(cust.id),
            "package_id": str(pkg.id),
            "valid_from": (now - timedelta(days=60)).isoformat(),
            "valid_until": (now + timedelta(days=30)).isoformat(),
            "modules": ["CORE"],
        },
        headers=hdrs,
    )
    lic_id = create_resp.json()["license_id"]
    lic = db_session.query(License).filter(License.id == UUID(lic_id)).first()
    lic.status = "EXPIRED"
    db_session.commit()

    resp = client.patch(
        f"/api/v1/licenses/{lic_id}/validity",
        json={
            "valid_from": (now - timedelta(days=60)).isoformat(),
            "valid_until": (now + timedelta(days=300)).isoformat(),
            "reason": "Koreksi tanggal kedaluwarsa",
        },
        headers=hdrs,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACTIVE"
