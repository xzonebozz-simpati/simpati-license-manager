"""Tes penegakan sisi server: status kedaluwarsa, restricted, nonce anti-replay, aktivasi."""
import json
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.models.license import LicenseInstallation
from app.models.security import RevocationRecord
from app.services.license_service import compute_license_status

from test_m2m_integration import _make_basic_auth, _setup_m2m_fixture


def _lic(status="ACTIVE", vu=30, grace=7):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        status=status, valid_from=now - timedelta(days=1),
        valid_until=None if vu is None else now + timedelta(days=vu), grace_period_days=grace,
    )


def test_compute_status_matrix():
    assert compute_license_status(_lic()) == "ACTIVE"
    assert compute_license_status(_lic(vu=-3)) == "GRACE_PERIOD"
    assert compute_license_status(_lic(vu=-10)) == "RESTRICTED"
    assert compute_license_status(_lic(vu=-1, grace=0)) == "RESTRICTED"
    assert compute_license_status(_lic(vu=None)) == "RESTRICTED"
    # override administratif menang atas tanggal (TERMINATED dulu terhitung ACTIVE)
    for st in ("TERMINATED", "EXPIRED", "DRAFT", "SUSPENDED", "REVOKED"):
        assert compute_license_status(_lic(status=st)) == st


def _bind_and_verify(client, db_session, mutate=None, nonce=None):
    fix = _setup_m2m_fixture(db_session)
    nonce = nonce or secrets.token_hex(32)
    db_session.add(LicenseInstallation(license_id=fix["license"].id,
                                       installation_id=fix["inst1"].id, is_active=True))
    if mutate:
        mutate(fix["license"])
    db_session.commit()
    resp = client.post(
        "/api/v1/validations/verify",
        json={"license_key": fix["license"].license_key,
              "installation_code": fix["inst1"].installation_code, "nonce": nonce,
              "timestamp": datetime.now(timezone.utc).isoformat()},
        headers=_make_basic_auth(fix["client_id"], fix["client_secret"]),
    )
    assert resp.status_code == 200, resp.text
    return fix, resp.json()


def test_expired_beyond_grace_is_restricted_and_blocks_writes(client, db_session):
    def expire(lic):
        lic.valid_until = datetime.now(timezone.utc) - timedelta(days=30)
    _, data = _bind_and_verify(client, db_session, expire)
    assert data["validation_status"] == "RESTRICTED"
    assert data["is_restricted_mode"] is True
    assert data["restricted_rules"]["write_mutations_blocked"] is True
    assert data["restricted_rules"]["public_registration_blocked"] is True


def test_within_grace_is_not_restricted(client, db_session):
    def expire(lic):
        lic.valid_until = datetime.now(timezone.utc) - timedelta(days=2)
    _, data = _bind_and_verify(client, db_session, expire)
    assert data["validation_status"] == "GRACE_PERIOD"
    assert data["is_restricted_mode"] is False


def test_terminated_and_draft_are_restricted(client, db_session):
    for st in ("TERMINATED", "DRAFT"):
        _, data = _bind_and_verify(client, db_session, lambda lic, st=st: setattr(lic, "status", st))
        assert data["is_restricted_mode"] is True, st


def test_crl_revocation_remains_effective_if_license_status_is_reset(client, db_session):
    def add_legacy_revocation(lic):
        lic.status = "ACTIVE"
        db_session.add(RevocationRecord(
            entity_type="LICENSE",
            entity_id=lic.id,
            revocation_code="REV-LIC-LEGACY",
            reason="Revokasi permanen untuk pengujian",
        ))

    _, data = _bind_and_verify(client, db_session, add_legacy_revocation)
    assert data["validation_status"] == "REVOKED"
    assert data["is_restricted_mode"] is True


def test_nonce_is_echoed_inside_signed_payload(client, db_session):
    _, data = _bind_and_verify(client, db_session, nonce="nonce-abcdef-001")
    assert data["payload"]["nonce"] == "nonce-abcdef-001"
    assert data["payload"]["license_key"] and data["payload"]["installation_code"]


def test_unbound_rejection_also_echoes_nonce(client, db_session):
    fix = _setup_m2m_fixture(db_session)
    resp = client.post(
        "/api/v1/validations/verify",
        json={"license_key": fix["license"].license_key,
              "installation_code": fix["inst1"].installation_code, "nonce": "nonce-unbound-01",
              "timestamp": datetime.now(timezone.utc).isoformat()},
        headers=_make_basic_auth(fix["client_id"], fix["client_secret"]),
    )
    data = resp.json()
    assert data["validation_status"] == "UNBOUND_INSTALLATION"
    assert data["payload"]["nonce"] == "nonce-unbound-01"


def test_validation_nonce_cannot_be_replayed(client, db_session):
    fix = _setup_m2m_fixture(db_session)
    db_session.add(LicenseInstallation(
        license_id=fix["license"].id,
        installation_id=fix["inst1"].id,
        is_active=True,
    ))
    db_session.commit()
    request_data = {
        "license_key": fix["license"].license_key,
        "installation_code": fix["inst1"].installation_code,
        "nonce": secrets.token_hex(32),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    headers = _make_basic_auth(fix["client_id"], fix["client_secret"])
    first = client.post("/api/v1/validations/verify", json=request_data, headers=headers)
    replay = client.post("/api/v1/validations/verify", json=request_data, headers=headers)
    assert first.status_code == 200
    assert replay.status_code == 409
