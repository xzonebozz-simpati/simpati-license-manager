"""Tests for the scoped Universal API service identity."""

import base64
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import SecretStr

from app.models.catalog import LicensePackage
from app.models.customer import Customer
from app.security import dependencies


SERVICE_ID = "simpati-universal-api"
SERVICE_SECRET = "service-secret-for-tests-0123456789-abcdef"


def _basic_auth(
    service_id: str = SERVICE_ID,
    secret: str = SERVICE_SECRET,
) -> dict[str, str]:
    token = base64.b64encode(
        f"{service_id}:{secret}".encode("utf-8")
    ).decode("ascii")
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


def test_service_can_issue_license_for_registered_customer_and_package(
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
    headers = _basic_auth()

    customer_list = client.get(
        "/api/v1/customers?skip=0&limit=100",
        headers=headers,
    )
    package_list = client.get(
        "/api/v1/packages?is_active=true&skip=0&limit=100",
        headers=headers,
    )
    package_detail = client.get(
        f"/api/v1/packages/{package.id}",
        headers=headers,
    )
    modules = client.get(
        "/api/v1/packages/modules/available",
        headers=headers,
    )

    assert customer_list.status_code == 200
    assert any(item["id"] == str(customer.id) for item in customer_list.json())
    assert package_list.status_code == 200
    assert any(item["id"] == str(package.id) for item in package_list.json())
    assert package_detail.status_code == 200
    assert package_detail.json()["package_modules"] == []
    assert modules.status_code == 200

    now = datetime.now(timezone.utc)
    created = client.post(
        "/api/v1/licenses",
        headers=headers,
        json={
            "customer_id": str(customer.id),
            "package_id": str(package.id),
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=30)).isoformat(),
            "modules": [],
            "levels": ["DPD"],
        },
    )
    assert created.status_code == 201, created.text
    license_id = created.json()["license_id"]

    listed = client.get(
        (
            f"/api/v1/licenses?customer_id={customer.id}"
            f"&package_id={package.id}&skip=0&limit=100"
        ),
        headers=headers,
    )
    detail = client.get(
        f"/api/v1/licenses/{license_id}",
        headers=headers,
    )
    assert listed.status_code == 200
    assert any(item["id"] == license_id for item in listed.json())
    assert detail.status_code == 200
    assert detail.json()["customer_id"] == str(customer.id)
    assert detail.json()["package_id"] == str(package.id)
    assert client.delete(
        f"/api/v1/licenses/{license_id}",
        headers=headers,
    ).status_code == 401


def test_service_scope_does_not_replace_superadmin_authentication(
    client,
    service_configuration,
):
    assert client.get("/api/v1/packages").status_code == 401
    assert client.get(
        "/api/v1/packages",
        headers=_basic_auth(secret="wrong-service-secret"),
    ).status_code == 401
    assert client.post(
        "/api/v1/packages",
        headers=_basic_auth(),
        json={
            "package_code": "PKG-SVC-DENIED",
            "package_name": "Service Must Not Create Packages",
        },
    ).status_code == 401

    login = client.post(
        "/api/v1/auth/login",
        json={"username": "superadmin", "password": "SuperAdmin@2026!"},
    )
    assert login.status_code == 200
    response = client.get(
        "/api/v1/packages",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert response.status_code == 200


def test_non_superadmin_session_cannot_access_scoped_license_routes(
    client,
    db_session,
):
    from app.models.user import LicenseUser
    from app.security.hashing import hash_password
    from app.services.auth_service import authenticate_user

    username = f"operator-{uuid4().hex[:8]}"
    operator = LicenseUser(
        username=username,
        email=f"{username}@example.test",
        full_name="Test Operator",
        password_hash=hash_password("OperatorSecret@2026!"),
        role="OPERATOR",
        is_active=True,
    )
    db_session.add(operator)
    db_session.commit()
    _, token, _ = authenticate_user(
        db_session,
        username,
        "OperatorSecret@2026!",
    )

    response = client.get(
        "/api/v1/packages",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
