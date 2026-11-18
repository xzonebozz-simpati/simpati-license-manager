"""Tests for the scoped SIMPATI Universal API service identity."""

import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import SecretStr

from app.models.catalog import LicensePackage
from app.models.customer import Customer
from app.models.operations import LicenseAuditLog
from app.security import dependencies


SERVICE_ID = "simpati-universal-api"
SERVICE_SECRET = "service-secret-for-tests-0123456789-abcdef"
ROTATED_SECRET = "rotated-service-secret-for-tests-0123456789"


def _basic_auth(service_id: str, secret: str) -> dict[str, str]:
    token = base64.b64encode(f"{service_id}:{secret}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def service_configuration(monkeypatch):
    settings = SimpleNamespace(
        UNIVERSAL_API_SERVICE_ID=SERVICE_ID,
        UNIVERSAL_API_SERVICE_SECRET=SecretStr(SERVICE_SECRET),
        UNIVERSAL_API_SERVICE_PREVIOUS_SECRET=None,
    )
    monkeypatch.setattr(dependencies, "get_settings", lambda: settings)
    return settings


def test_service_authentication_and_auth_audit(client, db_session, service_configuration):
    response = client.get(
        "/api/v1/customers",
        headers=_basic_auth(SERVICE_ID, SERVICE_SECRET),
    )

    assert response.status_code == 200
    log = (
        db_session.query(LicenseAuditLog)
        .filter_by(action_name="SERVICE_REQUEST_AUTHORIZED")
        .order_by(LicenseAuditLog.created_at.desc())
        .first()
    )
    assert log is not None
    assert log.user_id is None
    assert json.loads(log.details)["service_id"] == SERVICE_ID


def test_service_scope_rejects_ungranted_customer_detail(
    client,
    service_configuration,
):
    response = client.get(
        f"/api/v1/customers/{uuid4()}",
        headers=_basic_auth(SERVICE_ID, SERVICE_SECRET),
    )

    assert response.status_code == 401


def test_invalid_service_credentials_are_rejected(client, service_configuration):
    response = client.get(
        "/api/v1/customers",
        headers=_basic_auth(SERVICE_ID, "invalid-service-secret"),
    )

    assert response.status_code == 401
    assert "secret" not in response.text.lower()


def test_service_secret_rotation_and_revocation(
    client,
    service_configuration,
):
    service_configuration.UNIVERSAL_API_SERVICE_PREVIOUS_SECRET = SecretStr(
        SERVICE_SECRET
    )
    service_configuration.UNIVERSAL_API_SERVICE_SECRET = SecretStr(ROTATED_SECRET)

    old_secret_during_overlap = client.get(
        "/api/v1/customers",
        headers=_basic_auth(SERVICE_ID, SERVICE_SECRET),
    )
    new_secret = client.get(
        "/api/v1/customers",
        headers=_basic_auth(SERVICE_ID, ROTATED_SECRET),
    )
    assert old_secret_during_overlap.status_code == 200
    assert new_secret.status_code == 200

    service_configuration.UNIVERSAL_API_SERVICE_PREVIOUS_SECRET = None
    revoked_old_secret = client.get(
        "/api/v1/customers",
        headers=_basic_auth(SERVICE_ID, SERVICE_SECRET),
    )
    assert revoked_old_secret.status_code == 401


def test_service_license_routes_and_business_audit(
    client,
    db_session,
    service_configuration,
):
    suffix = uuid4().hex[:8]
    customer = Customer(
        customer_code=f"CUST-SVC-{suffix}",
        organization_name=f"Service Test {suffix}",
        contact_person="Service Test",
        contact_email=f"service-{suffix}@example.test",
    )
    package = LicensePackage(
        package_code=f"PKG-SVC-{suffix}",
        package_name=f"Service Package {suffix}",
    )
    db_session.add_all([customer, package])
    db_session.commit()

    now = datetime.now(timezone.utc)
    headers = _basic_auth(SERVICE_ID, SERVICE_SECRET)
    created = client.post(
        "/api/v1/licenses",
        headers=headers,
        json={
            "customer_id": str(customer.id),
            "package_id": str(package.id),
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=30)).isoformat(),
            "modules": ["CORE"],
            "levels": ["DPD"],
        },
    )
    assert created.status_code == 201, created.text
    license_id = created.json()["id"]

    listed = client.get(
        "/api/v1/licenses?limit=100&offset=0",
        headers=headers,
    )
    packages_listed = client.get(
        "/api/v1/packages?limit=100&offset=0",
        headers=headers,
    )
    detailed = client.get(f"/api/v1/licenses/{license_id}/detail", headers=headers)
    package_detail = client.get(
        f"/api/v1/packages/{package.id}/detail",
        headers=headers,
    )
    assert listed.status_code == 200
    assert any(item["id"] == license_id for item in listed.json())
    assert packages_listed.status_code == 200, packages_listed.text
    assert any(item["id"] == str(package.id) for item in packages_listed.json())
    assert detailed.status_code == 200
    assert package_detail.status_code == 200

    extended = client.post(
        f"/api/v1/licenses/{license_id}/extend",
        headers=headers,
        json={
            "valid_until": (now + timedelta(days=60)).isoformat(),
            "reason": "Service integration test extension",
        },
    )
    corrected = client.patch(
        f"/api/v1/licenses/{license_id}/validity",
        headers=headers,
        json={
            "valid_from": (now - timedelta(days=2)).isoformat(),
            "valid_until": (now + timedelta(days=90)).isoformat(),
            "reason": "Service integration test correction",
        },
    )
    status_changed = client.patch(
        f"/api/v1/licenses/{license_id}/status",
        headers=headers,
        json={
            "status": "SUSPENDED",
            "reason": "Service integration test suspension",
        },
    )
    assert extended.status_code == 200, extended.text
    assert corrected.status_code == 200, corrected.text
    assert status_changed.status_code == 200, status_changed.text

    events = (
        db_session.query(LicenseAuditLog)
        .filter(
            LicenseAuditLog.action_name.in_(
                [
                    "LICENSE_ISSUED",
                    "LICENSE_EXTENDED",
                    "LICENSE_VALIDITY_EDITED",
                    "LICENSE_STATUS_CHANGED",
                ]
            ),
            LicenseAuditLog.target_resource.like(f"license:%"),
        )
        .all()
    )
    service_events = [
        event
        for event in events
        if json.loads(event.details or "{}").get("service_id") == SERVICE_ID
    ]
    assert {
        event.action_name for event in service_events
    } >= {
        "LICENSE_ISSUED",
        "LICENSE_EXTENDED",
        "LICENSE_VALIDITY_EDITED",
        "LICENSE_STATUS_CHANGED",
    }


def test_user_session_authentication_remains_supported(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "superadmin", "password": "SuperAdmin@2026!"},
    )
    assert login.status_code == 200

    response = client.get("/api/v1/packages")
    assert response.status_code == 200
