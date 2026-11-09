"""Targeted integration tests for SIMPATI M2M authentication, binding validation, and Ed25519 signatures."""

import base64
import json
import secrets
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.models.customer import Customer
from app.models.installation import Installation, InstallationCredential
from app.models.catalog import LicensePackage
from app.models.license import License, LicenseInstallation
from app.schemas.license import LicenseCreate, LicenseCapacityInput
from app.services.license_service import issue_license
from app.security.hashing import hash_password


def _setup_m2m_fixture(db_session):
    """Sets up a customer, package, installation, and installation credentials."""
    uid = secrets.token_hex(4)
    now = datetime.now(timezone.utc)
    cust = Customer(
        customer_code=f"CUST-M2M-{uid}",
        organization_name=f"M2M Client Org {uid}",
        contact_person="M2M Admin",
        contact_email=f"m2m_{uid}@client.org"
    )
    pkg = LicensePackage(
        package_code=f"PKG-M2M-{uid}",
        package_name=f"Package M2M {uid}"
    )
    db_session.add_all([cust, pkg])
    db_session.commit()

    inst1 = Installation(
        customer_id=cust.id,
        installation_code=f"INST-M2M-001-{uid}",
        name="Primary Server",
        environment="PRODUCTION",
        status="ACTIVE"
    )
    inst2 = Installation(
        customer_id=cust.id,
        installation_code=f"INST-M2M-002-{uid}",
        name="Secondary Server",
        environment="PRODUCTION",
        status="ACTIVE"
    )
    db_session.add_all([inst1, inst2])
    db_session.commit()

    client_id = f"simpati_cred_{uid}_1"
    client_secret = f"SecretKey_Test_{uid}!"
    cred1 = InstallationCredential(
        installation_id=inst1.id,
        client_id=client_id,
        client_secret_hash=hash_password(client_secret),
        is_active=True
    )
    cred2 = InstallationCredential(
        installation_id=inst2.id,
        client_id=f"simpati_cred_{uid}_2",
        client_secret_hash=hash_password(f"SecretKey_Test_Other_{uid}!"),
        is_active=True
    )
    db_session.add_all([cred1, cred2])
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
        capacity=LicenseCapacityInput(max_members=50000, max_accounts=100)
    )
    lic = issue_license(db=db_session, data=lic_data)

    return {
        "customer": cust,
        "package": pkg,
        "inst1": inst1,
        "inst2": inst2,
        "client_id": client_id,
        "client_secret": client_secret,
        "license": lic
    }


def _make_basic_auth(client_id: str, client_secret: str) -> dict:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    return {"Authorization": f"Basic {b64}"}


def test_verify_requires_m2m_basic_auth(client, db_session):
    """Verify endpoint rejects requests without auth or with invalid secrets."""
    fix = _setup_m2m_fixture(db_session)

    # 1. No Authorization header -> 401
    resp = client.post(
        "/api/v1/validations/verify",
        json={"license_key": fix["license"].license_key, "installation_code": fix["inst1"].installation_code}
    )
    assert resp.status_code == 401

    # 2. Wrong Client Secret -> 401
    bad_headers = _make_basic_auth(fix["client_id"], "WrongSecretKey!")
    resp = client.post(
        "/api/v1/validations/verify",
        json={"license_key": fix["license"].license_key, "installation_code": fix["inst1"].installation_code},
        headers=bad_headers
    )
    assert resp.status_code == 401


def test_verify_blocks_installation_code_mismatch(client, db_session):
    """Credentials belong to inst1, but request body specifies inst2 -> 403 Forbidden."""
    fix = _setup_m2m_fixture(db_session)
    headers = _make_basic_auth(fix["client_id"], fix["client_secret"])

    resp = client.post(
        "/api/v1/validations/verify",
        json={
            "license_key": fix["license"].license_key,
            "installation_code": fix["inst2"].installation_code  # Mismatched!
        },
        headers=headers
    )
    assert resp.status_code == 403
    assert "tidak cocok dengan identitas kredensial terotentikasi" in resp.json()["detail"]


def test_verify_unbound_installation_rejected_with_signature(client, db_session):
    """When license is not bound to installation in license_installations, returns UNBOUND_INSTALLATION with signature."""
    fix = _setup_m2m_fixture(db_session)
    headers = _make_basic_auth(fix["client_id"], fix["client_secret"])

    resp = client.post(
        "/api/v1/validations/verify",
        json={"license_key": fix["license"].license_key, "installation_code": fix["inst1"].installation_code},
        headers=headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["validation_status"] == "UNBOUND_INSTALLATION"
    assert data["is_restricted_mode"] is True
    assert "signature" in data
    assert data["signature"] is not None
    assert "payload" in data


def test_verify_bound_license_success_with_ed25519_signature(client, db_session):
    """When properly bound, verify succeeds, returns ACTIVE and a verifiable Ed25519 signature."""
    fix = _setup_m2m_fixture(db_session)

    # Bind license to inst1
    binding = LicenseInstallation(
        license_id=fix["license"].id,
        installation_id=fix["inst1"].id,
        is_active=True
    )
    db_session.add(binding)
    db_session.commit()

    headers = _make_basic_auth(fix["client_id"], fix["client_secret"])
    resp = client.post(
        "/api/v1/validations/verify",
        json={"license_key": fix["license"].license_key, "installation_code": fix["inst1"].installation_code},
        headers=headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["validation_status"] == "ACTIVE"
    assert data["is_restricted_mode"] is False
    assert "CORE" in data["allowed_modules"]
    assert "signature" in data
    assert "payload" in data

    # Verify signature against public key from endpoint
    pub_resp = client.get("/api/v1/licenses/root-public-key")
    assert pub_resp.status_code == 200
    pub_pem = pub_resp.json()["public_key_pem"]

    public_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
    assert isinstance(public_key, ed25519.Ed25519PublicKey)

    canonical_bytes = json.dumps(data["payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_bytes = bytes.fromhex(data["signature"])

    # This will raise InvalidSignature if verification fails
    public_key.verify(sig_bytes, canonical_bytes)


def test_verify_bound_to_different_installation_is_unbound(client, db_session):
    """If license is bound to inst2, inst1 cannot use it even with valid inst1 credentials."""
    fix = _setup_m2m_fixture(db_session)

    # Bind license to inst2 instead
    binding = LicenseInstallation(
        license_id=fix["license"].id,
        installation_id=fix["inst2"].id,
        is_active=True
    )
    db_session.add(binding)
    db_session.commit()

    # inst1 requests verify for the license
    headers = _make_basic_auth(fix["client_id"], fix["client_secret"])
    resp = client.post(
        "/api/v1/validations/verify",
        json={"license_key": fix["license"].license_key, "installation_code": fix["inst1"].installation_code},
        headers=headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["validation_status"] == "UNBOUND_INSTALLATION"
    assert data["is_restricted_mode"] is True


def test_heartbeat_m2m_auth_and_spoof_prevention(client, db_session):
    """Heartbeat requires HTTP Basic Auth and prevents identity mismatch."""
    fix = _setup_m2m_fixture(db_session)

    # 1. No auth -> 401
    resp = client.post(
        "/api/v1/installations/heartbeat",
        json={"installation_code": fix["inst1"].installation_code, "metrics": {}}
    )
    assert resp.status_code == 401

    # 2. Wrong auth -> 401
    bad_headers = _make_basic_auth(fix["client_id"], "BadPassword")
    resp = client.post(
        "/api/v1/installations/heartbeat",
        json={"installation_code": fix["inst1"].installation_code, "metrics": {}},
        headers=bad_headers
    )
    assert resp.status_code == 401

    # 3. Mismatched code -> 403
    headers1 = _make_basic_auth(fix["client_id"], fix["client_secret"])
    resp = client.post(
        "/api/v1/installations/heartbeat",
        json={"installation_code": fix["inst2"].installation_code, "metrics": {}},
        headers=headers1
    )
    assert resp.status_code == 403
    assert "tidak cocok dengan identitas kredensial terotentikasi" in resp.json()["detail"]

    # 4. Correct auth & code -> 200 ACKNOWLEDGED
    resp = client.post(
        "/api/v1/installations/heartbeat",
        json={
            "installation_code": fix["inst1"].installation_code,
            "metrics": {"db_size_mb": 120, "active_users_last_hour": 15}
        },
        headers=headers1
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACKNOWLEDGED"
