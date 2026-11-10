"""Comprehensive Real Integration Test between SIMPATI 555 and SIMPATI LICENSE MANAGER.

Tests all 9 points with real database credentials, real Ed25519 cryptography,
HEX and Base64 signature verification, offline grace, and middleware enforcement.
"""

import base64
import json
import os
import secrets
import sys
import tempfile
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from starlette.testclient import TestClient
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# License Manager imports
from app.main import create_application as create_license_manager_app
from app.database.session import SessionLocal
from app.models.installation import Installation, InstallationCredential
from app.models.license import License
from app.services.validation_service import get_or_load_root_signing_keys, _sign_payload_canonical

# SIMPATI 555 Client imports
from app.client.license_client import (
    LicenseConfig,
    LicenseClient,
    LicenseRestrictedMiddleware
)


def run_full_integration_audit():
    print("=" * 80)
    print("AUDIT & PENGUJIAN INTEGRASI NYATA: SIMPATI 555 <-> SIMPATI LICENSE MANAGER")
    print("=" * 80)

    db = SessionLocal()
    lm_app = create_license_manager_app()
    lm_client = TestClient(lm_app)

    # ------------------------------------------------------------------------
    # 0. Ambil Kredensial Nyata dari Database License Manager
    # ------------------------------------------------------------------------
    inst = db.query(Installation).filter(Installation.installation_code == "INST-2026-DPD-01").first()
    assert inst is not None, "Instalasi INST-2026-DPD-01 harus ada dalam database!"

    cred = db.query(InstallationCredential).filter(
        InstallationCredential.installation_id == inst.id,
        InstallationCredential.is_active == True
    ).first()
    assert cred is not None, "Kredensial aktif untuk INST-2026-DPD-01 harus ada!"

    lic = db.query(License).filter(License.license_key == "SMP-LIC-2026-A1B2-C3D4").first()
    assert lic is not None, "Lisensi SMP-LIC-2026-A1B2-C3D4 harus ada dalam database!"

    # We know the plain client secret rotated earlier:
    client_id = cred.client_id
    # If the active credential is the one we rotated:
    # Let's ensure we have the exact plain secret:
    from app.services.installation_service import rotate_installation_credentials
    client_id, client_secret = rotate_installation_credentials(db, inst.id)

    print(f"[0] Kredensial Nyata Terverifikasi:")
    print(f"    - Installation Code: {inst.installation_code}")
    print(f"    - License Key      : {lic.license_key}")
    print(f"    - Client ID        : {client_id}")
    print(f"    - Client Secret    : {client_secret[:6]}...{client_secret[-6:]}")

    _, root_pub_pem = get_or_load_root_signing_keys()

    # Siapkan file cache pengujian terisolasi
    tmp_dir = Path(tempfile.mkdtemp())
    cache_path = tmp_dir / "simpati_live_cache.json"

    cfg = LicenseConfig(
        license_manager_url="http://license-manager.local",
        license_key=lic.license_key,
        installation_code=inst.installation_code,
        client_id=client_id,
        client_secret=client_secret,
        public_key_pem=root_pub_pem,
        cache_file_path=cache_path,
        offline_grace_period_days=7
    )

    client = LicenseClient(config=cfg)

    # Custom transport adapter to route LicenseClient's urllib calls through TestClient
    def mock_urlopen(req, timeout=15):
        url = req.full_url
        path = url.replace(cfg.license_manager_url, "")
        headers = dict(req.headers)
        data = req.data
        if data:
            data = data.decode("utf-8") if isinstance(data, bytes) else data

        method = req.get_method()
        if method == "POST":
            resp = lm_client.post(path, data=data, headers=headers)
        else:
            resp = lm_client.get(path, headers=headers)

        class MockResponse:
            def __init__(self, r):
                self._r = r
                self.status = r.status_code
            def read(self):
                return self._r.content
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        if resp.status_code >= 400:
            import urllib.error
            raise urllib.error.HTTPError(url, resp.status_code, resp.text, resp.headers, None)

        return MockResponse(resp)

    # ------------------------------------------------------------------------
    # PENGUJIAN 1: Validasi Lisensi Aktif Berhasil & Kesesuaian HEX + Base64
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 1] Validasi Lisensi Aktif & Format Signature (HEX & Base64) ---")
    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res1 = client.validate_online()

    assert res1["validation_status"] == "ACTIVE", f"Harusnya ACTIVE, dapat: {res1['validation_status']}"
    assert res1["is_restricted_mode"] is False, "Restricted mode harus False!"
    assert res1["signature"] is not None, "Signature harus ada!"

    sig_hex = res1["signature"]
    payload1 = res1["payload"]

    # Verifikasi format HEX (128 karakter)
    assert len(sig_hex) == 128, f"Signature HEX harus 128 karakter, panjang: {len(sig_hex)}"
    assert client.verify_signature(payload1, sig_hex) is True
    print("  [OK] Verifikasi tanda tangan format HEX (128 char): SUKSES")

    # Verifikasi format Base64 (86-88 karakter)
    sig_b64 = base64.b64encode(bytes.fromhex(sig_hex)).decode("ascii")
    assert client.verify_signature(payload1, sig_b64) is True
    print(f"  [OK] Verifikasi tanda tangan format Base64 ({len(sig_b64)} char): SUKSES")
    print(f"  [OK] Validasi online status: {res1['validation_status']} (RestrictedMode={res1['is_restricted_mode']})")

    # ------------------------------------------------------------------------
    # PENGUJIAN 2: Modul yang Tidak Tercantum dalam Lisensi Ditolak
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 2] Gating Modul yang Tercantum vs Tidak Tercantum ---")
    entitled_modules = res1["allowed_modules"]
    print(f"  Modul yang diizinkan dalam lisensi: {entitled_modules}")

    # Modul resmi dalam paket
    assert client.is_module_allowed("CORE") is True
    assert client.is_module_allowed("SURVEI_GPS") is True
    print("  [OK] Modul sah ('CORE', 'SURVEI_GPS'): DIIZINKAN")

    # Modul di luar lisensi
    assert client.is_module_allowed("FINANCIAL_LEDGER") is False
    assert client.is_module_allowed("AI_PREDICTIVE_ANALYTICS") is False
    print("  [OK] Modul tidak tercantum ('FINANCIAL_LEDGER', 'AI_PREDICTIVE_ANALYTICS'): DITOLAK")

    # ------------------------------------------------------------------------
    # PENGUJIAN 3: Tanda Tangan Ed25519 Palsu Ditolak
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 3] Tanda Tangan Ed25519 Palsu/Tampered Ditolak ---")
    # Kasus A: Signature korup
    corrupt_sig = "a" * 128
    tampered_caught = False
    try:
        client.verify_signature(payload1, corrupt_sig)
    except InvalidSignature:
        tampered_caught = True
    assert tampered_caught is True, "Signature palsu harus melempar InvalidSignature!"
    print("  [OK] Signature sembarang/palsu: Berhasil dideteksi dan DITOLAK")

    # Kasus B: Payload dimanipulasi (misal mencoba mengubah status lisensi)
    tampered_payload = dict(payload1)
    tampered_payload["validation_status"] = "ACTIVE_LIFETIME"
    tampered_caught_b = False
    try:
        client.verify_signature(tampered_payload, sig_hex)
    except InvalidSignature:
        tampered_caught_b = True
    assert tampered_caught_b is True, "Manipulasi payload harus melempar InvalidSignature!"
    print("  [OK] Manipulasi payload response: Berhasil dideteksi dan DITOLAK")

    # ------------------------------------------------------------------------
    # PENGUJIAN 4: Cache Lisensi Tidak Dapat Dimanipulasi Tanpa Terdeteksi
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 4] Proteksi Anti-Tamper Cache Lisensi Lokal ---")
    assert cache_path.exists(), "Cache file harus terbentuk setelah validasi online!"
    valid_cache = client.load_cached_state()
    assert valid_cache is not None, "Cache sah harus berhasil dimuat"
    print("  [OK] Cache sah berhasil dimuat dan diverifikasi signaturenya.")

    # Simulasikan pengguna mengubah cache file secara manual di disk
    cache_raw = json.loads(cache_path.read_text(encoding="utf-8"))
    cache_raw["payload"]["is_restricted_mode"] = False
    cache_raw["payload"]["validation_status"] = "HACKED_UNLIMITED"
    cache_path.write_text(json.dumps(cache_raw), encoding="utf-8")

    tampered_cache_loaded = client.load_cached_state()
    assert tampered_cache_loaded is None, "Cache yang diedit manual harus ditolak (return None)!"
    print("  [OK] Cache lokal yang diedit manual langsung DITOLAK (InvalidSignature).")

    # ------------------------------------------------------------------------
    # PENGUJIAN 5: Internet Terputus: SIMPATI Tetap Beroperasi (Offline Grace 7 Hari)
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 5] Internet Terputus: Offline Grace Period (7 Hari) ---")
    # Pulihkan cache yang sah dengan timestamp baru (misal 1 hari lalu)
    recent_time = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    valid_payload = dict(payload1)
    valid_payload["validated_at"] = recent_time
    valid_sig = _sign_payload_canonical(valid_payload)
    valid_state = {
        "validation_status": "ACTIVE",
        "license_key": cfg.license_key,
        "installation_code": cfg.installation_code,
        "is_restricted_mode": False,
        "is_offline": False,
        "allowed_modules": ["CORE", "SURVEI_GPS"],
        "validated_at": recent_time,
        "payload": valid_payload,
        "signature": valid_sig
    }
    client.save_cache_state(valid_state)

    # Simulasikan server offline
    with patch("urllib.request.urlopen", side_effect=Exception("Connection refused (Server Down)")):
        offline_res = client.validate_online()

    assert offline_res["validation_status"] == "GRACE_PERIOD", f"Status harus GRACE_PERIOD, dapat: {offline_res['validation_status']}"
    assert offline_res["is_restricted_mode"] is False, "Selama offline grace, Restricted Mode TIDAK boleh aktif!"
    assert offline_res["is_offline"] is True, "Flag is_offline harus True!"
    assert offline_res["grace_type"] == "OFFLINE_GRACE", f"Grace type harus OFFLINE_GRACE, dapat: {offline_res['grace_type']}"
    print(f"  [OK] Server offline (1 hari sejak validasi terakhir):")
    print(f"       Status={offline_res['validation_status']}, RestrictedMode={offline_res['is_restricted_mode']}, GraceType={offline_res['grace_type']}")

    # ------------------------------------------------------------------------
    # PENGUJIAN 6: Offline Grace Habis: Restricted Mode Aktif
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 6] Offline Grace Habis (> 7 Hari): Restricted Mode Aktif ---")
    # Simulasikan cache validasi terakhir dilakukan 8 hari lalu
    expired_time = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    expired_payload = dict(payload1)
    expired_payload["validated_at"] = expired_time
    expired_sig = _sign_payload_canonical(expired_payload)
    expired_state = {
        "validation_status": "ACTIVE",
        "license_key": cfg.license_key,
        "installation_code": cfg.installation_code,
        "is_restricted_mode": False,
        "is_offline": False,
        "allowed_modules": ["CORE", "SURVEI_GPS"],
        "validated_at": expired_time,
        "payload": expired_payload,
        "signature": expired_sig
    }
    client.save_cache_state(expired_state)

    with patch("urllib.request.urlopen", side_effect=Exception("Connection refused (Server Down)")):
        expired_offline_res = client.validate_online()

    assert expired_offline_res["validation_status"] == "RESTRICTED", f"Harus RESTRICTED, dapat: {expired_offline_res['validation_status']}"
    assert expired_offline_res["is_restricted_mode"] is True, "Restricted Mode harus AKTIF!"
    assert client.is_restricted_mode() is True
    print(f"  [OK] Server offline (>7 hari sejak validasi terakhir):")
    print(f"       Status={expired_offline_res['validation_status']}, RestrictedMode={expired_offline_res['is_restricted_mode']}")

    # ------------------------------------------------------------------------
    # PENGUJIAN 7: Internet Pulih: Validasi Otomatis Kembali Normal
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 7] Internet Pulih: Otomatis Kembali Normal (ACTIVE) ---")
    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        recovered_res = client.validate_online()

    assert recovered_res["validation_status"] == "ACTIVE", f"Harus kembali ACTIVE, dapat: {recovered_res['validation_status']}"
    assert recovered_res["is_restricted_mode"] is False, "Restricted mode harus dinonaktifkan kembali!"
    assert client.is_restricted_mode() is False
    print(f"  [OK] Koneksi pulih: Lisensi otomatis normal kembali (Status={recovered_res['validation_status']}, RestrictedMode=False)")

    # ------------------------------------------------------------------------
    # PENGUJIAN 8: Grace Period Lisensi Kedaluwarsa Dibedakan dari Offline Grace
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 8] Membedakan Grace Period Kontrak vs Offline Grace ---")
    # Kasus A: Kontrak kedaluwarsa tapi online (Server memberi status GRACE_PERIOD)
    contract_grace_payload = {
        "license_key": cfg.license_key,
        "installation_code": cfg.installation_code,
        "validation_status": "GRACE_PERIOD",
        "is_restricted_mode": False
    }
    contract_grace_sig = _sign_payload_canonical(contract_grace_payload)
    mock_server_contract_grace = {
        "validation_token": "val_contract_grace",
        "validation_status": "GRACE_PERIOD",
        "is_restricted_mode": False,
        "allowed_modules": ["CORE"],
        "payload": contract_grace_payload,
        "signature": contract_grace_sig
    }

    def mock_contract_grace_urlopen(req, timeout=15):
        class MockResp:
            status = 200
            def read(self):
                return json.dumps(mock_server_contract_grace).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        return MockResp()

    with patch("urllib.request.urlopen", side_effect=mock_contract_grace_urlopen):
        cg_res = client.validate_online()

    assert cg_res["validation_status"] == "GRACE_PERIOD"
    assert cg_res["is_offline"] is False
    assert cg_res["grace_type"] == "CONTRACT_GRACE"
    print(f"  [OK] Kontrak Lisensi Kedaluwarsa (Online):")
    print(f"       Status={cg_res['validation_status']}, is_offline={cg_res['is_offline']}, grace_type={cg_res['grace_type']}")

    # Kasus B: Masalah Jaringan (Offline Grace)
    # Gunakan state sebelumnya
    client.save_cache_state(valid_state)
    with patch("urllib.request.urlopen", side_effect=Exception("Timeout")):
        og_res = client.validate_online()

    assert og_res["validation_status"] == "GRACE_PERIOD"
    assert og_res["is_offline"] is True
    assert og_res["grace_type"] == "OFFLINE_GRACE"
    print(f"  [OK] Masalah Jaringan Terputus (Offline Grace):")
    print(f"       Status={og_res['validation_status']}, is_offline={og_res['is_offline']}, grace_type={og_res['grace_type']}")
    print("  [OK] Kedua kondisi grace period berhasil dibedakan secara tegas.")

    # ------------------------------------------------------------------------
    # PENGUJIAN 9: Hak Baca, Ekspor, & Backup Tetap Tersedia dalam Restricted Mode
    # ------------------------------------------------------------------------
    print("\n--- [PENGUJIAN 9] Hak Baca, Ekspor & Backup Tetap Berjalan di Restricted Mode ---")
    from fastapi import FastAPI

    simpati_test_app = FastAPI(title="SIMPATI 555 Test")

    # Paksa client dalam Restricted Mode
    client._cached_state = {
        "validation_status": "RESTRICTED",
        "is_restricted_mode": True,
        "allowed_modules": []
    }
    simpati_test_app.add_middleware(LicenseRestrictedMiddleware, client=client)

    # Definisikan rute representatif SIMPATI 555
    @simpati_test_app.get("/admin")
    def get_admin_dashboard():
        return {"page": "dashboard", "content": "Daftar 100 Anggota 555"}

    @simpati_test_app.get("/admin/export.csv")
    def export_csv():
        return "id,nama,nik\n1,Budi,123456"

    @simpati_test_app.get("/admin/rekap.pdf")
    def export_pdf():
        return b"%PDF-1.4 Mock PDF Content"

    @simpati_test_app.post("/admin/login")
    def admin_login():
        return {"status": "success", "session": "active"}

    @simpati_test_app.post("/api/pendaftaran")
    def pendaftaran_baru():
        return {"status": "created", "id": 101}

    @simpati_test_app.post("/admin/anggota/1/edit")
    def edit_anggota():
        return {"status": "updated"}

    simpati_tc = TestClient(simpati_test_app)

    # 1. Hak Baca Data
    r_read = simpati_tc.get("/admin")
    assert r_read.status_code == 200, f"Harus 200 OK, dapat: {r_read.status_code}"
    print("  [OK] GET /admin (Hak Baca Data): 200 OK")

    # 2. Hak Ekspor CSV
    r_csv = simpati_tc.get("/admin/export.csv")
    assert r_csv.status_code == 200, f"Harus 200 OK, dapat: {r_csv.status_code}"
    assert "Budi" in r_csv.text
    print("  [OK] GET /admin/export.csv (Hak Ekspor Data): 200 OK")

    # 3. Hak Backup PDF
    r_pdf = simpati_tc.get("/admin/rekap.pdf")
    assert r_pdf.status_code == 200, f"Harus 200 OK, dapat: {r_pdf.status_code}"
    assert b"%PDF" in r_pdf.content
    print("  [OK] GET /admin/rekap.pdf (Hak Backup Dokumen): 200 OK")

    # 4. Hak Login
    r_login = simpati_tc.post("/admin/login")
    assert r_login.status_code == 200, f"Harus 200 OK, dapat: {r_login.status_code}"
    print("  [OK] POST /admin/login (Hak Autentikasi Pengurus): 200 OK")

    # 5. Mutasi Pendaftaran Baru (DIBLOKIR)
    r_daftar = simpati_tc.post("/api/pendaftaran", json={"nama": "Pendaftar Baru"})
    assert r_daftar.status_code == 403, f"Harus 403 Forbidden, dapat: {r_daftar.status_code}"
    assert r_daftar.json()["restricted_mode"] is True
    print(f"  [OK] POST /api/pendaftaran (Mutasi Pendaftaran Baru): 403 DIBLOKIR ({r_daftar.json()['detail'][:35]}...)")

    # 6. Mutasi Edit Anggota (DIBLOKIR)
    r_edit = simpati_tc.post("/admin/anggota/1/edit", data={"nama": "Ubah Nama"})
    assert r_edit.status_code == 403, f"Harus 403 Forbidden, dapat: {r_edit.status_code}"
    print("  [OK] POST /admin/anggota/1/edit (Mutasi Perubahan Data): 403 DIBLOKIR")

    print("\n" + "=" * 80)
    print("KESIMPULAN: SELURUH 9 POIN PENGUJIAN INTEGRASI BERHASIL 100%!")
    print("=" * 80)
    db.close()

if __name__ == "__main__":
    run_full_integration_audit()
