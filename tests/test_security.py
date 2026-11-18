"""Tests for Argon2id hashing, Ed25519 digital signature, and tokens."""

import logging
import pytest
from app.security.hashing import hash_password, verify_password, needs_rehash
from app.security.crypto import (
    generate_ed25519_keypair,
    sign_payload,
    verify_signature,
    generate_secure_token,
    hash_token
)


def test_argon2id_hashing():
    """Verifies that password hashing uses Argon2id and verification passes."""
    password = "SuperSecurePassword@2026!"
    hashed = hash_password(password)

    # Argon2id header verification
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False
    assert needs_rehash(hashed) is False


def test_argon2id_empty_password_rejection():
    """Verifies that empty passwords raise ValueError."""
    with pytest.raises(ValueError):
        hash_password("")


def test_ed25519_keypair_generation_and_signature():
    """Verifies Ed25519 asymmetric signature generation and verification."""
    priv_pem, pub_pem = generate_ed25519_keypair()
    assert "BEGIN PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem

    payload = b'{"license_key": "SMP-LIC-2026-TEST", "valid_until": "2027-11-09"}'
    signature = sign_payload(priv_pem, payload)
    assert len(signature) > 0

    # Verification must succeed with valid public key
    assert verify_signature(pub_pem, payload, signature) is True

    # Verification must fail if payload is tampered
    tampered_payload = b'{"license_key": "SMP-LIC-2026-TEST", "valid_until": "2035-11-09"}'
    assert verify_signature(pub_pem, tampered_payload, signature) is False


def test_generated_license_key_has_at_least_128_bits_of_entropy():
    from app.services.license_service import generate_license_key

    parts = generate_license_key().split("-")
    assert len(parts) == 5
    assert len(parts[3]) == 16
    assert len(parts[4]) == 16


def test_production_settings_reject_bootstrap_secrets():
    from pydantic import ValidationError
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(
            APP_ENV="production",
            ADMIN_PASSWORD="SuperAdmin@2026!",
            SECRET_KEY="simpati-super-secret-key-change-in-production-min-32-chars",
        )


def test_secret_key_startup_diagnostic_logs_metadata_only(monkeypatch, caplog, tmp_path):
    from app.config import _log_secret_key_diagnostics

    secret_key = "never-log-this-secret-key-value"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("SECRET_KEY", secret_key)

    with caplog.at_level(logging.WARNING):
        _log_secret_key_diagnostics()

    assert secret_key not in caplog.text
    assert "APP_ENV=staging" in caplog.text
    assert "SECRET_KEY available=True" in caplog.text
    assert "length=31" in caplog.text
    assert "placeholder=False default=False" in caplog.text


def test_signing_key_startup_diagnostic_logs_metadata_only(monkeypatch, caplog, tmp_path):
    from scripts import init_db

    private_key = (
        "-----BEGIN PRIVATE KEY-----\nprivate-test-material\n-----END PRIVATE KEY-----"
    )
    public_key = (
        "-----BEGIN PUBLIC KEY-----\npublic-test-material\n-----END PUBLIC KEY-----"
    )
    vault_path = tmp_path / "root.key"
    vault_path.write_text("test", encoding="utf-8")
    vault_path.with_suffix(".pub").write_text("test", encoding="utf-8")
    monkeypatch.setattr(init_db.settings, "ED25519_PRIVATE_KEY_PEM", private_key)
    monkeypatch.setattr(init_db.settings, "ED25519_PUBLIC_KEY_PEM", public_key)
    monkeypatch.setattr(init_db.settings, "SIGNING_KEY_VAULT_PATH", str(vault_path))

    with caplog.at_level(logging.WARNING):
        init_db._log_signing_key_diagnostics()

    assert private_key not in caplog.text
    assert public_key not in caplog.text
    assert "private_env_present=True" in caplog.text
    assert f"private_env_length={len(private_key)}" in caplog.text
    assert "private_env_pem_markers_ok=True" in caplog.text
    assert "public_env_present=True" in caplog.text
    assert f"public_env_length={len(public_key)}" in caplog.text
    assert "public_env_pem_markers_ok=True" in caplog.text
    assert "vault_private_file_exists=True" in caplog.text
    assert "vault_public_file_exists=True" in caplog.text


def test_root_signing_keys_reject_mismatched_environment_pair(monkeypatch, tmp_path):
    from app.services import license_service

    private_pem, _ = license_service.generate_ed25519_keypair()
    _, different_public_pem = license_service.generate_ed25519_keypair()
    monkeypatch.setattr(license_service.settings, "ED25519_PRIVATE_KEY_PEM", private_pem)
    monkeypatch.setattr(license_service.settings, "ED25519_PUBLIC_KEY_PEM", different_public_pem)
    monkeypatch.setattr(license_service.settings, "SIGNING_KEY_VAULT_PATH", str(tmp_path / "root.key"))

    with pytest.raises(ValueError, match="do not match"):
        license_service.get_or_load_root_signing_keys()


def test_token_generation_and_hashing():
    """Verifies cryptographic token generator and SHA-256 hash lookup."""
    token1 = generate_secure_token(32)
    token2 = generate_secure_token(32)
    assert token1 != token2

    h1 = hash_token(token1)
    assert len(h1) == 64
    assert h1 == hash_token(token1)
