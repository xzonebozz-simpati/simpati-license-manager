"""Comprehensive audit and tests for authentication, session lifecycle, and CSRF."""

import uuid
from app.models.customer import Customer
from app.models.user import LicenseUser
from app.security.hashing import hash_password


def test_dashboard_without_login_redirects_to_login(client):
    """Verifies unauthenticated visitors are redirected to the login page."""
    # When visiting / without session
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")

    # Protected routes must also redirect
    for route in ["/customers", "/installations", "/licenses", "/settings"]:
        resp = client.get(route, follow_redirects=False)
        assert resp.status_code == 303
        assert "/login" in resp.headers["location"]


def test_login_with_invalid_credentials_rejected(client):
    """Verifies login attempts with wrong credentials fail with 401."""
    # First get login page to obtain a valid CSRF token
    login_page = client.get("/login")
    assert login_page.status_code == 200
    csrf_token = client.cookies.get("simpati_csrf_token")
    assert csrf_token is not None

    # Submit wrong password
    response = client.post(
        "/login",
        data={
            "username": "superadmin",
            "password": "WrongPassword123!",
            "csrf_token": csrf_token
        }
    )
    assert response.status_code == 401
    assert "Nama pengguna atau kata sandi tidak valid" in response.text
    # Ensure no session cookie was granted
    assert "simpati_session" not in response.cookies


def test_login_with_valid_credentials_establishes_session(client, db_session):
    """Verifies login with correct credentials creates a valid session and cookies."""
    # Ensure superadmin exists in test DB
    admin = db_session.query(LicenseUser).filter(LicenseUser.username == "superadmin").first()
    if not admin:
        admin = LicenseUser(
            username="superadmin",
            email="superadmin@simpati.id",
            full_name="SIMPATI License Superadmin",
            password_hash=hash_password("SuperAdmin@2026!"),
            role="SUPERADMIN",
            is_active=True
        )
        db_session.add(admin)
        db_session.commit()

    login_page = client.get("/login")
    csrf_token = client.cookies.get("simpati_csrf_token")

    # POST credentials
    response = client.post(
        "/login",
        data={
            "username": "superadmin",
            "password": "SuperAdmin@2026!",
            "csrf_token": csrf_token,
            "next": "/customers"
        },
        follow_redirects=False
    )

    # Must redirect to target
    assert response.status_code == 303
    assert response.headers["location"] == "/customers"

    # Must set secure session cookie
    assert "simpati_session" in client.cookies
    assert client.cookies.get("simpati_session") is not None


def test_session_grants_access_to_dashboard_and_views(client, db_session):
    """Verifies that an authenticated session can view the dashboard and management pages."""
    # Authenticate via API login to populate client session
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "superadmin", "password": "SuperAdmin@2026!"}
    )
    assert login_resp.status_code == 200
    assert "simpati_session" in client.cookies

    # Now accessing / must succeed with 200 OK
    dash_resp = client.get("/")
    assert dash_resp.status_code == 200
    assert "Dashboard" in dash_resp.text
    assert "Ringkasan Operasional" in dash_resp.text

    # Accessing /customers must succeed
    cust_resp = client.get("/customers")
    assert cust_resp.status_code == 200
    assert "Daftar Pelanggan" in cust_resp.text


def test_customer_creation_after_login(client):
    """Verifies that saving a customer succeeds when authenticated with session and CSRF."""
    # Login
    client.post(
        "/api/v1/auth/login",
        json={"username": "superadmin", "password": "SuperAdmin@2026!"}
    )
    csrf_token = client.cookies.get("simpati_csrf_token")
    assert csrf_token is not None

    cust_code = f"CUST-AUTH-{uuid.uuid4().hex[:6]}"
    payload = {
        "customer_code": cust_code,
        "organization_name": "Organisasi Mitra Terverifikasi",
        "contact_person": "Drs. Hendra Setiawan",
        "contact_email": "hendra@mitra.org",
        "contact_phone": "+628129876543",
        "address": "Gedung SIMPATI Lt. 5, Bandung",
        "notes": "Pendaftaran sukses pasca autentikasi"
    }

    # 1. Attempt without CSRF header when session cookie is active -> Expect 403 Forbidden
    rejected_res = client.post("/api/v1/customers", json=payload)
    assert rejected_res.status_code == 403
    assert "CSRF" in rejected_res.json()["detail"]

    # 2. Attempt with CSRF header -> Expect 201 Created
    success_res = client.post(
        "/api/v1/customers",
        json=payload,
        headers={"X-CSRF-Token": csrf_token}
    )
    assert success_res.status_code == 201
    data = success_res.json()
    assert data["customer_code"] == cust_code
    assert data["organization_name"] == payload["organization_name"]


def test_logout_terminates_session_and_subsequent_access_blocked(client):
    """Verifies logout revokes the session and blocks subsequent dashboard access."""
    # 1. Login
    client.post(
        "/api/v1/auth/login",
        json={"username": "superadmin", "password": "SuperAdmin@2026!"}
    )
    assert client.get("/").status_code == 200

    # 2. Logout via GET /logout
    logout_resp = client.get("/logout", follow_redirects=False)
    assert logout_resp.status_code == 303
    assert "/login" in logout_resp.headers["location"]

    # 3. Subsequent access to / must be redirected to /login
    followup_resp = client.get("/", follow_redirects=False)
    assert followup_resp.status_code == 303
    assert "/login" in followup_resp.headers["location"]
