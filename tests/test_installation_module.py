"""Unit and integration tests for SIMPATI Installation Management Module (Iteration 4)."""

import pytest
from uuid import uuid4
from fastapi.testclient import TestClient

from app.models.customer import Customer
from app.models.installation import Installation, InstallationCredential, InstallationEvent
from app.models.license import License, LicenseInstallation
from app.models.user import LicenseUser
from app.security.hashing import hash_password
from app.services.auth_service import authenticate_user


SAMPLE_ED25519_PUBKEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA9rN+q2q8O9kQ2qE4y5U7cQ9N1aW3v4X5Z6y7A8b9c0E=\n"
    "-----END PUBLIC KEY-----\n"
)


@pytest.fixture
def auth_headers(db_session):
    """Provides authorization cookie and CSRF headers for authenticated Superadmin requests."""
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
def sample_customer(db_session):
    """Creates a sample customer organization with a unique customer code for each test."""
    unique_suffix = uuid4().hex[:6].upper()
    cust = Customer(
        customer_code=f"CUST-{unique_suffix}",
        organization_name=f"Sinode Jawa Barat {unique_suffix}",
        contact_person="Bpk. Pendeta Yohanes",
        contact_email=f"yohanes.{unique_suffix.lower()}@sinodejabar.test",
        contact_phone="08123456789",
        status="ACTIVE"
    )
    db_session.add(cust)
    db_session.commit()
    db_session.refresh(cust)
    return cust


def test_create_installation_success(client: TestClient, auth_headers, sample_customer):
    """Tests creating a new installation under a customer with auto-generated code and initial credentials."""
    payload = {
        "customer_id": str(sample_customer.id),
        "name": "Server SIMPATI Jabar Utama",
        "environment": "PRODUCTION",
        "server_domain": "simpati.sinodejabar.test",
        "server_ip": "103.14.22.10",
        "hardware_signature": "MB-SN-99881122"
    }
    resp = client.post(
        "/api/v1/installations",
        json=payload,
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert resp.status_code == 201
    data = resp.json()

    assert data["name"] == "Server SIMPATI Jabar Utama"
    assert data["customer_id"] == str(sample_customer.id)
    assert data["environment"] == "PRODUCTION"
    assert data["installation_code"].startswith("INST-")
    assert "client_id" in data
    assert data["client_id"].startswith("CLT-")
    assert "client_secret" in data
    assert len(data["client_secret"]) > 20
    assert "enrollment_token" in data


def test_create_installation_duplicate_code_fails(client: TestClient, auth_headers, sample_customer):
    """Tests that registering an installation with an already existing code returns 400."""
    unique_code = f"INST-UNIQ-{uuid4().hex[:4].upper()}"
    payload = {
        "customer_id": str(sample_customer.id),
        "installation_code": unique_code,
        "name": "Server Primer",
        "environment": "PRODUCTION"
    }
    # First creation: success
    resp1 = client.post(
        "/api/v1/installations",
        json=payload,
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert resp1.status_code == 201

    # Second creation with identical code: fails
    resp2 = client.post(
        "/api/v1/installations",
        json=payload,
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert resp2.status_code == 400
    assert "sudah terdaftar" in resp2.json()["detail"]


def test_installation_public_key_registration(client: TestClient, auth_headers, sample_customer):
    """Tests registering an Ed25519 public key and verifying its fingerprint."""
    reg_resp = client.post(
        "/api/v1/installations",
        json={"customer_id": str(sample_customer.id), "name": "Server Kripto"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    inst_id = reg_resp.json()["id"]

    # Register valid PEM public key
    pk_resp = client.post(
        f"/api/v1/installations/{inst_id}/public-key",
        json={"public_key_pem": SAMPLE_ED25519_PUBKEY},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert pk_resp.status_code == 200
    assert pk_resp.json()["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")

    # Verify detail shows fingerprint
    det_resp = client.get(
        f"/api/v1/installations/{inst_id}/detail",
        headers={"Cookie": auth_headers["cookie"]}
    )
    assert det_resp.status_code == 200
    det_data = det_resp.json()
    assert det_data["has_public_key"] is True
    assert det_data["public_key_fingerprint"] is not None
    assert len(det_data["public_key_fingerprint"]) == 16


def test_installation_status_lifecycle_and_events(client: TestClient, auth_headers, sample_customer):
    """Tests suspending and reactivating an installation, and verifying event history."""
    reg_resp = client.post(
        "/api/v1/installations",
        json={"customer_id": str(sample_customer.id), "name": "Server Status Test"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    inst_id = reg_resp.json()["id"]

    # 1. Suspend
    suspend_resp = client.patch(
        f"/api/v1/installations/{inst_id}/status",
        json={"status": "SUSPENDED", "reason": "Audit rutin tahunan"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert suspend_resp.status_code == 200
    assert suspend_resp.json()["status"] == "SUSPENDED"

    # 2. Reactivate
    active_resp = client.patch(
        f"/api/v1/installations/{inst_id}/status",
        json={"status": "ACTIVE", "reason": "Selesai audit operasional"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert active_resp.status_code == 200
    assert active_resp.json()["status"] == "ACTIVE"

    # 3. Check Detail Events
    det_resp = client.get(f"/api/v1/installations/{inst_id}/detail", headers={"Cookie": auth_headers["cookie"]})
    events = det_resp.json()["events"]
    event_types = [e["event_type"] for e in events]
    assert "REGISTERED" in event_types
    assert "STATUS_CHANGED" in event_types


def test_installation_rotate_credentials(client: TestClient, auth_headers, sample_customer):
    """Tests rotating API credentials for an installation."""
    reg_resp = client.post(
        "/api/v1/installations",
        json={"customer_id": str(sample_customer.id), "name": "Server Rotasi Kredensial"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    inst_id = reg_resp.json()["id"]
    old_client_id = reg_resp.json()["client_id"]

    # Rotate credentials
    rot_resp = client.post(
        f"/api/v1/installations/{inst_id}/rotate-credentials",
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert rot_resp.status_code == 200
    rot_data = rot_resp.json()
    new_client_id = rot_data["client_id"]
    assert new_client_id != old_client_id
    assert "client_secret" in rot_data

    # Verify detail shows 2 credentials (1 active, 1 revoked)
    det_resp = client.get(f"/api/v1/installations/{inst_id}/detail", headers={"Cookie": auth_headers["cookie"]})
    creds = det_resp.json()["credentials"]
    assert len(creds) == 2
    active_creds = [c for c in creds if c["is_active"]]
    revoked_creds = [c for c in creds if not c["is_active"]]
    assert len(active_creds) == 1
    assert len(revoked_creds) == 1
    assert active_creds[0]["client_id"] == new_client_id


def test_installation_heartbeat_telemetry(client: TestClient, auth_headers, sample_customer):
    """Tests machine-to-machine heartbeat telemetry ping from a remote SIMPATI installation."""
    reg_resp = client.post(
        "/api/v1/installations",
        json={"customer_id": str(sample_customer.id), "name": "Server Telemetry Live"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    inst_data = reg_resp.json()
    inst_code = inst_data["installation_code"]
    inst_id = inst_data["id"]

    # Heartbeat is an exempt M2M endpoint authenticated via HTTP Basic Auth
    import base64
    client_id = inst_data["client_id"]
    client_secret = inst_data["client_secret"]
    m2m_auth = "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

    hb_payload = {
        "installation_code": inst_code,
        "current_version": "555.2.4",
        "active_user_count": 42,
        "total_members_recorded": 1250,
        "status_summary": "OPTIMAL"
    }
    hb_resp = client.post(
        "/api/v1/installations/heartbeat",
        json=hb_payload,
        headers={"Authorization": m2m_auth}
    )
    assert hb_resp.status_code == 200
    assert hb_resp.json()["status"] == "ACKNOWLEDGED"

    # Verify heartbeat timestamp updated in detail
    det_resp = client.get(f"/api/v1/installations/{inst_id}/detail", headers={"Cookie": auth_headers["cookie"]})
    assert det_resp.status_code == 200
    det_data = det_resp.json()
    assert det_data["last_heartbeat_at"] is not None


def test_installation_delete_removes_bindings_and_preserves_license(client: TestClient, db_session, auth_headers, sample_customer):
    """Deleting an installation removes its bindings without deleting the commercial license."""
    from datetime import datetime, timezone, timedelta
    from app.models.catalog import LicensePackage
    pkg = db_session.query(LicensePackage).first()
    assert pkg is not None

    # 1. Create installation
    reg_resp = client.post(
        "/api/v1/installations",
        json={"customer_id": str(sample_customer.id), "name": "Server Terikat Lisensi"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    inst_id = reg_resp.json()["id"]

    # 2. Create and link a license directly in DB
    from uuid import UUID
    now = datetime.now(timezone.utc)
    lic = License(
        customer_id=sample_customer.id,
        package_id=pkg.id,
        license_key=f"SIMPATI-LIC-{uuid4().hex[:6].upper()}",
        license_type="PERPETUAL",
        valid_from=now,
        valid_until=now + timedelta(days=365)
    )
    db_session.add(lic)
    db_session.flush()

    link = LicenseInstallation(
        license_id=lic.id,
        installation_id=UUID(inst_id),
        is_active=True
    )
    db_session.add(link)
    db_session.commit()

    # 3. Delete installation and ensure only its related records are removed.
    del_resp = client.delete(
        f"/api/v1/installations/{inst_id}",
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    assert del_resp.status_code == 200
    assert "ikatan lisensi dihapus" in del_resp.json()["message"]
    assert db_session.query(License).filter(License.id == lic.id).first() is not None
    assert db_session.query(LicenseInstallation).filter(LicenseInstallation.id == link.id).first() is None


def test_installation_enrollment_config(client: TestClient, auth_headers, sample_customer):
    """Tests generating enrollment configuration and .env template."""
    reg_resp = client.post(
        "/api/v1/installations",
        json={"customer_id": str(sample_customer.id), "name": "Server Integrasi Enrolment"},
        headers={"X-CSRF-Token": auth_headers["X-CSRF-Token"], "Cookie": auth_headers["cookie"]}
    )
    inst_id = reg_resp.json()["id"]

    cfg_resp = client.get(
        f"/api/v1/installations/{inst_id}/enrollment",
        headers={"Cookie": auth_headers["cookie"]}
    )
    assert cfg_resp.status_code == 200
    cfg_data = cfg_resp.json()
    assert "license_server_url" in cfg_data
    assert "SIMPATI_INSTALLATION_CODE" in cfg_data["recommended_env"]
    assert "SIMPATI_CLIENT_ID" in cfg_data["recommended_env"]
