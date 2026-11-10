"""Tests for SIMPATI 555 License Client integration, Ed25519 verification, and Restricted Mode."""

import base64
import json
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI
from starlette.testclient import TestClient

from app.client.license_client import (
    LicenseConfig,
    LicenseClient,
    LicenseRestrictedMiddleware
)
from app.services.validation_service import _sign_payload_canonical, get_or_load_root_signing_keys
from app.security.hashing import hash_password
from app.models.customer import Customer
from app.models.catalog import LicensePackage
from app.models.installation import Installation, InstallationCredential
from app.models.license import License, LicenseInstallation
from app.schemas.license import LicenseCreate, LicenseCapacityInput
from app.services.license_service import issue_license


def test_license_client_config_defaults():
    cfg = LicenseConfig(
        license_manager_url="https://license.simpati.id",
        license_key="SMP-TEST-KEY",
        installation_code="INST-TEST-01",
        client_id="CID-TEST",
        client_secret="sec_test_123"
    )
    assert cfg.license_manager_url == "https://license.simpati.id"
    assert cfg.license_key == "SMP-TEST-KEY"
    assert cfg.installation_code == "INST-TEST-01"
    assert cfg.client_id == "CID-TEST"
    assert cfg.client_secret == "sec_test_123"
    assert cfg.offline_grace_period_days == 7


def test_build_auth_header():
    cfg = LicenseConfig(
        client_id="my_client_id",
        client_secret="my_client_secret",
        installation_code="INST-999"
    )
    client = LicenseClient(config=cfg)
    headers = client._build_auth_header()

    assert "Authorization" in headers
    auth_val = headers["Authorization"]
    assert auth_val.startswith("Basic ")
    b64_part = auth_val[6:]
    decoded = base64.b64decode(b64_part).decode("utf-8")
    assert decoded == "my_client_id:my_client_secret"
    assert headers["Content-Type"] == "application/json"


def test_verify_signature_valid_and_tampered():
    _, pub_pem = get_or_load_root_signing_keys()
    cfg = LicenseConfig(public_key_pem=pub_pem)
    client = LicenseClient(config=cfg)

    payload = {
        "license_key": "SMP-TEST-KEY",
        "installation_code": "INST-TEST-01",
        "validation_status": "ACTIVE",
        "is_restricted_mode": False
    }

    sig_hex = _sign_payload_canonical(payload)

    # 1. Valid signature passes
    assert client.verify_signature(payload, sig_hex) is True

    # 2. Tampered payload raises InvalidSignature
    tampered_payload = dict(payload)
    tampered_payload["is_restricted_mode"] = True  # modified

    with pytest.raises(InvalidSignature):
        client.verify_signature(tampered_payload, sig_hex)


def test_cache_persistence_and_tamper_detection(tmp_path):
    _, pub_pem = get_or_load_root_signing_keys()
    cache_file = tmp_path / "test_cache.json"

    cfg = LicenseConfig(
        public_key_pem=pub_pem,
        cache_file_path=cache_file
    )
    client = LicenseClient(config=cfg)

    payload = {
        "license_key": "SMP-CACHED-KEY",
        "installation_code": "INST-CACHED-01",
        "validation_status": "ACTIVE",
        "is_restricted_mode": False
    }
    sig_hex = _sign_payload_canonical(payload)

    state = {
        "validation_status": "ACTIVE",
        "is_restricted_mode": False,
        "allowed_modules": ["CORE_MEMBERSHIP", "SURVEI_GPS"],
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
        "signature": sig_hex
    }

    # Save cache
    client.save_cache_state(state)
    assert cache_file.exists()

    # Load cache (valid)
    loaded = client.load_cached_state()
    assert loaded is not None
    assert loaded["validation_status"] == "ACTIVE"

    # Tamper with cached file manually
    raw_data = json.loads(cache_file.read_text(encoding="utf-8"))
    raw_data["payload"]["validation_status"] = "REVOKED"
    cache_file.write_text(json.dumps(raw_data), encoding="utf-8")

    # Load cache should detect tampering and return None
    loaded_tampered = client.load_cached_state()
    assert loaded_tampered is None


def test_offline_grace_period_handling(tmp_path):
    _, pub_pem = get_or_load_root_signing_keys()
    cache_file = tmp_path / "test_offline.json"

    cfg = LicenseConfig(
        public_key_pem=pub_pem,
        cache_file_path=cache_file,
        offline_grace_period_days=7
    )
    client = LicenseClient(config=cfg)

    # 1. Recent validation: within 7 days -> Enter GRACE_PERIOD, NOT restricted
    recent_time = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    payload = {
        "license_key": "SMP-KEY",
        "installation_code": "INST-01",
        "validated_at": recent_time
    }
    state = {
        "validation_status": "ACTIVE",
        "is_restricted_mode": False,
        "validated_at": recent_time,
        "payload": payload,
        "signature": _sign_payload_canonical(payload)
    }
    client.save_cache_state(state)

    res = client._handle_validation_offline()
    assert res["validation_status"] == "GRACE_PERIOD"
    assert res["is_restricted_mode"] is False

    # 2. Old validation: beyond 7 days (e.g. 10 days ago) -> Enter RESTRICTED
    old_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    payload_old = {
        "license_key": "SMP-KEY",
        "installation_code": "INST-01",
        "validated_at": old_time
    }
    state_old = {
        "validation_status": "ACTIVE",
        "is_restricted_mode": False,
        "validated_at": old_time,
        "payload": payload_old,
        "signature": _sign_payload_canonical(payload_old)
    }
    client.save_cache_state(state_old)

    res_expired = client._handle_validation_offline()
    assert res_expired["validation_status"] == "RESTRICTED"
    assert res_expired["is_restricted_mode"] is True


def test_restricted_middleware_enforcement():
    # Setup mock client in restricted mode
    mock_client = MagicMock()
    mock_client.is_restricted_mode.return_value = True
    mock_client.get_license_state.return_value = {
        "validation_status": "RESTRICTED",
        "is_restricted_mode": True
    }

    app = FastAPI()
    app.add_middleware(LicenseRestrictedMiddleware, client=mock_client)

    @app.get("/daftar")
    def get_daftar():
        return {"status": "ok", "message": "halaman daftar"}

    @app.get("/admin/export.csv")
    def get_export():
        return {"status": "ok", "message": "export csv"}

    @app.post("/admin/login")
    def post_login():
        return {"status": "ok", "message": "login success"}

    @app.post("/api/pendaftaran")
    def post_daftar():
        return {"status": "created"}

    client = TestClient(app)

    # 1. GET requests allowed (read / export preserved)
    res_get = client.get("/daftar")
    assert res_get.status_code == 200

    res_export = client.get("/admin/export.csv")
    assert res_export.status_code == 200

    # 2. Auth POST allowed
    res_login = client.post("/admin/login")
    assert res_login.status_code == 200

    # 3. Operational mutation POST blocked (HTTP 403 Restricted Mode)
    res_mutate = client.post("/api/pendaftaran", json={"nama": "Anggota Baru"})
    assert res_mutate.status_code == 403
    data = res_mutate.json()
    assert data["restricted_mode"] is True
    assert "Restricted Mode" in data["detail"]


def test_module_and_capacity_checks():
    mock_client = MagicMock()
    mock_client.is_restricted_mode.return_value = False
    mock_client.get_license_state.return_value = {
        "validation_status": "ACTIVE",
        "is_restricted_mode": False,
        "allowed_modules": ["CORE_MEMBERSHIP", "OFFICERS_MANAGEMENT"],
        "capacity": {
            "max_members": 1000,
            "max_accounts": 10
        }
    }

    # Use concrete LicenseClient methods with mock state
    real_client = LicenseClient.__new__(LicenseClient)
    real_client.get_license_state = mock_client.get_license_state

    # Check modules
    assert real_client.is_module_allowed("CORE_MEMBERSHIP") is True
    assert real_client.is_module_allowed("OFFICERS_MANAGEMENT") is True
    assert real_client.is_module_allowed("SURVEI_GPS") is False

    # Check capacity
    assert real_client.is_capacity_exceeded("max_members", 500) is False
    assert real_client.is_capacity_exceeded("max_members", 1000) is True
    assert real_client.is_capacity_exceeded("max_accounts", 15) is True
