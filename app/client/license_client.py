"""SIMPATI 555 Client Integration & Enforcement Module.

Menghubungkan aplikasi SIMPATI 555 ke SIMPATI LICENSE MANAGER:
1. Konfigurasi kredensial M2M (Client ID, Client Secret, Installation Code, License Key).
2. Autentikasi HTTP Basic Auth & pengiriman payload canonical ke endpoint verifikasi.
3. Verifikasi tanda tangan digital Ed25519 anti-tamper.
4. Penyimpanan status lisensi lokal, offline grace period, dan penegakan Restricted Mode.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, HTMLResponse

logger = logging.getLogger("simpati.license_client")


# ============================================================================
# 1. Konfigurasi Klien Lisensi (Point 1)
# ============================================================================

DEFAULT_EMBEDDED_PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAjh++nc9ibA6aA8sgleuMEIfKew6WvWduo/uV+AEeplU=\n"
    "-----END PUBLIC KEY-----\n"
)

@dataclass
class LicenseConfig:
    """Konfigurasi integrasi SIMPATI 555 dengan License Manager."""
    license_manager_url: str = field(
        default_factory=lambda: os.getenv("LICENSE_MANAGER_URL", "http://127.0.0.1:8000").rstrip("/")
    )
    license_key: str = field(
        default_factory=lambda: os.getenv("SIMPATI_LICENSE_KEY", "SMP-LIC-2026-A1B2-C3D4")
    )
    installation_code: str = field(
        default_factory=lambda: os.getenv("SIMPATI_INSTALLATION_CODE", "INST-2026-DPD-01")
    )
    client_id: str = field(
        default_factory=lambda: os.getenv("SIMPATI_CLIENT_ID", "")
    )
    client_secret: str = field(
        default_factory=lambda: os.getenv("SIMPATI_CLIENT_SECRET", "")
    )
    public_key_pem: str = field(
        default_factory=lambda: os.getenv("LICENSE_MANAGER_PUBLIC_KEY", DEFAULT_EMBEDDED_PUBLIC_KEY)
    )
    cache_file_path: Path = field(
        default_factory=lambda: Path(os.getenv("SIMPATI_LICENSE_CACHE_FILE", ".license_cache.json"))
    )
    offline_grace_period_days: int = field(
        default_factory=lambda: int(os.getenv("SIMPATI_OFFLINE_GRACE_DAYS", "7"))
    )
    heartbeat_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("SIMPATI_HEARTBEAT_INTERVAL", "3600"))
    )


# ============================================================================
# 2 & 3. Klien M2M, Kriptografi Ed25519 & Cache Lokal (Point 2, 3, 4, 5)
# ============================================================================

class LicenseClient:
    """Klien M2M resmi untuk validasi dan penegakan lisensi SIMPATI 555."""

    def __init__(self, config: Optional[LicenseConfig] = None):
        self.config = config or LicenseConfig()
        self._lock = threading.Lock()
        self._bg_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._cached_state: Optional[Dict[str, Any]] = None

        # Load cache awal jika ada
        self._cached_state = self.load_cached_state()

    # ------------------------------------------------------------------------
    # Autentikasi & Pengiriman HTTP (Point 2 & 3)
    # ------------------------------------------------------------------------
    def _build_auth_header(self) -> Dict[str, str]:
        """Menyusun header HTTP Basic Auth untuk kredensial mesin M2M."""
        raw_cred = f"{self.config.client_id}:{self.config.client_secret}"
        encoded_cred = base64.b64encode(raw_cred.encode("utf-8")).decode("ascii")
        return {
            "Authorization": f"Basic {encoded_cred}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"SIMPATI-555-Client/{self.config.installation_code}"
        }

    def fetch_root_public_key(self) -> Optional[str]:
        """Mengambil kunci publik Ed25519 resmi dari License Manager."""
        url = f"{self.config.license_manager_url}/api/v1/licenses/root-public-key"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                pub_pem = data.get("public_key_pem")
                if pub_pem:
                    self.config.public_key_pem = pub_pem
                    logger.info("Berhasil menyinkronkan kunci publik Ed25519 dari server pusat.")
                    return pub_pem
        except Exception as exc:
            logger.warning(f"Gagal mengambil root public key dari server: {exc}")
        return self.config.public_key_pem

    # ------------------------------------------------------------------------
    # Verifikasi Tanda Tangan Ed25519 (Point 4)
    # ------------------------------------------------------------------------
    def verify_signature(self, payload: Dict[str, Any], signature_hex: str) -> bool:
        """Memverifikasi signature Ed25519 terhadap payload kanonikal anti-tamper.

        Raises:
            InvalidSignature: jika tanda tangan digital tidak cocok atau data dimanipulasi.
            ValueError: jika kunci publik atau signature cacat format.
        """
        if not self.config.public_key_pem:
            self.fetch_root_public_key()

        pub_key = serialization.load_pem_public_key(self.config.public_key_pem.encode("utf-8"))
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature_bytes = bytes.fromhex(signature_hex)

        pub_key.verify(signature_bytes, canonical_bytes)
        return True

    # ------------------------------------------------------------------------
    # Validasi Online (Point 2, 3, 4, 5)
    # ------------------------------------------------------------------------
    def validate_online(self) -> Dict[str, Any]:
        """Mengirim permintaan validasi online ke License Manager.

        Menggunakan HTTP Basic Auth dan memverifikasi tanda tangan Ed25519.
        Hasil validasi disimpan ke cache lokal anti-tamper.
        """
        url = f"{self.config.license_manager_url}/api/v1/validations/verify"
        req_payload = {
            "license_key": self.config.license_key,
            "installation_code": self.config.installation_code,
            "nonce": f"simpati-{secrets.token_hex(8)}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(req_payload).encode("utf-8"),
            headers=self._build_auth_header(),
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as http_err:
            try:
                err_body = json.loads(http_err.read().decode("utf-8"))
                detail = err_body.get("detail", str(http_err))
            except Exception:
                detail = str(http_err)
            logger.error(f"Gagal verifikasi lisensi (HTTP {http_err.code}): {detail}")
            return self._handle_validation_failure(f"HTTP {http_err.code}: {detail}")
        except Exception as exc:
            logger.error(f"Koneksi ke License Manager terputus / gagal: {exc}")
            return self._handle_validation_offline()

        # Verifikasi Ed25519 Signature
        sig_hex = resp_data.get("signature")
        payload = resp_data.get("payload")

        if not sig_hex or not payload:
            logger.critical("Respons License Manager tidak menyertakan tanda tangan digital Ed25519!")
            return self._handle_validation_failure("Missing Ed25519 signature in response")

        try:
            self.verify_signature(payload, sig_hex)
            logger.info("Verifikasi tanda tangan digital Ed25519 SUKSES.")
        except InvalidSignature:
            logger.critical("PEMALSUAN DETEKSI: Tanda tangan digital Ed25519 lisensi TIDAK VALID!")
            return self._handle_validation_failure("Tampered license payload detected (Invalid Signature)")
        except Exception as exc:
            logger.error(f"Kesalahan verifikasi signature: {exc}")
            return self._handle_validation_failure(f"Signature verification error: {exc}")

        # Simpan ke cache lokal
        cached = {
            "validation_status": resp_data.get("validation_status", "UNKNOWN"),
            "license_key": self.config.license_key,
            "installation_code": self.config.installation_code,
            "is_restricted_mode": bool(resp_data.get("is_restricted_mode", False)),
            "allowed_modules": resp_data.get("allowed_modules", []),
            "allowed_levels": resp_data.get("allowed_levels", []),
            "capacity": resp_data.get("capacity", {}),
            "restricted_rules": resp_data.get("restricted_rules", {}),
            "next_validation_due": resp_data.get("next_validation_due"),
            "validation_token": resp_data.get("validation_token"),
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
            "signature": sig_hex
        }

        self.save_cache_state(cached)
        with self._lock:
            self._cached_state = cached

        logger.info(
            f"Lisensi valid: Status={cached['validation_status']}, "
            f"RestrictedMode={'AKTIF' if cached['is_restricted_mode'] else 'NON-AKTIF'}"
        )
        return cached

    # ------------------------------------------------------------------------
    # Telemetri Heartbeat Berkala (Point 2)
    # ------------------------------------------------------------------------
    def send_heartbeat(self, metrics: Optional[Dict[str, Any]] = None) -> bool:
        """Mengirim telemetri keaktifan server (heartbeat) ke License Manager."""
        url = f"{self.config.license_manager_url}/api/v1/installations/heartbeat"
        body = {
            "installation_code": self.config.installation_code,
            "system_metrics": metrics or {
                "python_version": "3.11",
                "app_version": "555-v2.0",
                "os": os.name
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=self._build_auth_header(),
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    logger.debug("Heartbeat telemetri berhasil terkirim.")
                    return True
        except Exception as exc:
            logger.warning(f"Gagal mengirim heartbeat ke License Manager: {exc}")
        return False

    # ------------------------------------------------------------------------
    # Manajemen Cache Lokal & Offline Grace Period (Point 5)
    # ------------------------------------------------------------------------
    def save_cache_state(self, state: Dict[str, Any]) -> None:
        """Menyimpan status lisensi ke file cache lokal."""
        try:
            self.config.cache_file_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.cache_file_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error(f"Gagal menyimpan cache lisensi lokal: {exc}")

    def load_cached_state(self) -> Optional[Dict[str, Any]]:
        """Membaca cache lisensi lokal dan memverifikasi integritas signaturenya."""
        if not self.config.cache_file_path.exists():
            return None

        try:
            data = json.loads(self.config.cache_file_path.read_text(encoding="utf-8"))
            payload = data.get("payload")
            sig_hex = data.get("signature")
            if payload and sig_hex:
                self.verify_signature(payload, sig_hex)
                return data
            else:
                logger.warning("Cache lisensi lokal tidak memiliki signature yang sah.")
                return None
        except Exception as exc:
            logger.warning(f"Integritas cache lisensi lokal rusak/invalid: {exc}")
            return None

    def _handle_validation_offline(self) -> Dict[str, Any]:
        """Menangani kegagalan koneksi dengan skema Offline Grace Period."""
        cached = self.load_cached_state()
        now = datetime.now(timezone.utc)

        if cached and cached.get("validated_at"):
            try:
                last_dt = datetime.fromisoformat(cached["validated_at"])
                grace_limit = last_dt + timedelta(days=self.config.offline_grace_period_days)
                if now <= grace_limit:
                    logger.warning(
                        f"Server License Manager offline. Mengaktifkan Masa Tenggang Offline hingga {grace_limit.isoformat()}."
                    )
                    cached["validation_status"] = "GRACE_PERIOD"
                    cached["is_restricted_mode"] = False
                    with self._lock:
                        self._cached_state = cached
                    return cached
            except Exception:
                pass

        # Di luar masa tenggang atau tidak ada cache valid: Masuk ke RESTRICTED MODE
        logger.critical("Masa tenggang offline telah habis atau cache tidak sah. Memasuki RESTRICTED MODE.")
        restricted_state = {
            "validation_status": "RESTRICTED",
            "is_restricted_mode": True,
            "allowed_modules": [],
            "allowed_levels": [],
            "capacity": {},
            "restricted_rules": {
                "login_allowed": True,
                "read_data_allowed": True,
                "export_backup_allowed": True,
                "write_mutations_blocked": True,
                "account_modifications_blocked": True,
                "uploads_blocked": True,
                "public_registration_blocked": True
            },
            "validated_at": now.isoformat()
        }
        with self._lock:
            self._cached_state = restricted_state
        return restricted_state

    def _handle_validation_failure(self, reason: str) -> Dict[str, Any]:
        """Menangani respons penolakan dari server atau signature tidak valid."""
        now = datetime.now(timezone.utc)
        failed_state = {
            "validation_status": "RESTRICTED",
            "is_restricted_mode": True,
            "message": reason,
            "allowed_modules": [],
            "allowed_levels": [],
            "capacity": {},
            "restricted_rules": {
                "login_allowed": True,
                "read_data_allowed": True,
                "export_backup_allowed": True,
                "write_mutations_blocked": True,
                "account_modifications_blocked": True,
                "uploads_blocked": True,
                "public_registration_blocked": True
            },
            "validated_at": now.isoformat()
        }
        with self._lock:
            self._cached_state = failed_state
        return failed_state

    # ------------------------------------------------------------------------
    # Status & Pemeriksaan Izin (Point 5)
    # ------------------------------------------------------------------------
    def get_license_state(self) -> Dict[str, Any]:
        """Mengambil status lisensi saat ini (dari cache atau verifikasi online)."""
        with self._lock:
            if self._cached_state:
                return self._cached_state
        return self.validate_online()

    def is_restricted_mode(self) -> bool:
        """Memeriksa apakah sistem saat ini berada dalam Restricted Mode."""
        state = self.get_license_state()
        return bool(state.get("is_restricted_mode", False))

    def is_module_allowed(self, module_code: str) -> bool:
        """Memeriksa apakah modul tertentu diizinkan oleh paket lisensi aktif."""
        state = self.get_license_state()
        if state.get("is_restricted_mode", False):
            return False
        modules = state.get("allowed_modules", [])
        return module_code in modules

    def is_capacity_exceeded(self, capacity_key: str, current_count: int) -> bool:
        """Memeriksa apakah batas kuota/kapasitas telah terlampaui."""
        state = self.get_license_state()
        capacity = state.get("capacity", {})
        limit = capacity.get(capacity_key)
        if limit is not None and current_count >= limit:
            return True
        return False

    # ------------------------------------------------------------------------
    # Background Sync Daemon
    # ------------------------------------------------------------------------
    def start_background_sync(self) -> None:
        """Menjalankan thread background untuk validasi berkala dan telemetri."""
        if self._bg_thread and self._bg_thread.is_alive():
            return

        def _worker():
            logger.info("Background License Sync Daemon SIMPATI 555 aktif.")
            while not self._stop_event.is_set():
                try:
                    self.validate_online()
                    self.send_heartbeat()
                except Exception as e:
                    logger.warning(f"Error pada loop sync lisensi: {e}")

                self._stop_event.wait(timeout=self.config.heartbeat_interval_seconds)

        self._bg_thread = threading.Thread(target=_worker, daemon=True, name="simpati-license-worker")
        self._bg_thread.start()

    def stop_background_sync(self) -> None:
        """Menghentikan thread background sync."""
        self._stop_event.set()
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=2)


# ============================================================================
# 4. Middleware Penegakan Restricted Mode di FastAPI (Point 5)
# ============================================================================

_global_client: Optional[LicenseClient] = None

def get_license_client() -> LicenseClient:
    """Singleton getter untuk LicenseClient."""
    global _global_client
    if _global_client is None:
        _global_client = LicenseClient()
    return _global_client


class LicenseRestrictedMiddleware(BaseHTTPMiddleware):
    """Middleware FastAPI untuk penegakan Restricted Mode pada SIMPATI 555.

    Prinsip Restricted Mode:
    - Login admin/superadmin: TETAP BISA AKSES.
    - Pembacaan data anggota & wilayah: TETAP BISA DIAKSES.
    - Ekspor data CSV/PDF/Rekap: TETAP BISA DIUNDUH (jaminan kedaulatan data pelanggan).
    - Akses mutasi data (pendaftaran baru, buat akun, edit, hapus, upload berkas): DIBLOKIR.
    """

    def __init__(self, app, client: Optional[LicenseClient] = None):
        super().__init__(app)
        self.client = client or get_license_client()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method.upper()

        # Lewatkan permintaan statis & branding
        if path.startswith("/static") or path.startswith("/branding"):
            return await call_next(request)

        # Cek apakah Restricted Mode aktif
        if self.client.is_restricted_mode():
            # 1. Izinkan metode baca data (GET, HEAD, OPTIONS)
            if method in ["GET", "HEAD", "OPTIONS"]:
                response = await call_next(request)
                return response

            # 2. Izinkan autentikasi (login & logout)
            auth_whitelist = [
                "/admin/login",
                "/admin/logout",
                "/superadmin/login",
                "/superadmin/logout"
            ]
            if path in auth_whitelist:
                return await call_next(request)

            # 3. Blokir semua mutasi data operasional (POST, PUT, PATCH, DELETE)
            logger.warning(
                f"RESTRICTED MODE: Memblokir mutasi {method} {path} karena lisensi tidak aktif/terbatas."
            )

            # Jika permintaan API / JSON
            if "application/json" in request.headers.get("accept", "") or path.startswith("/api/"):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": (
                            "Sistem SIMPATI 555 sedang dalam Mode Terbatas (Restricted Mode). "
                            "Operasi penulisan, pendaftaran, dan mutasi data ditangguhkan. "
                            "Silakan perpanjang lisensi Anda melalui SIMPATI License Manager."
                        ),
                        "restricted_mode": True,
                        "status": self.client.get_license_state().get("validation_status", "RESTRICTED")
                    }
                )

            # Jika pengiriman form HTML biasa
            error_html = (
                "<!DOCTYPE html>"
                "<html><head><meta charset='utf-8'><title>Mode Terbatas - SIMPATI 555</title>"
                "<style>body{font-family:sans-serif;background:#1a1012;color:#f3f4f6;display:flex;align-items:center;"
                "justify-content:center;height:100vh;margin:0;} .card{background:#2b151a;border:1px solid #7f1d1d;"
                "padding:32px;border-radius:12px;max-width:540px;text-align:center;box-shadow:0 10px 25px rgba(0,0,0,0.5);}"
                "h2{color:#f87171;margin-top:0;} p{color:#d1d5db;line-height:1.6;} .btn{display:inline-block;"
                "background:#991b1b;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;margin-top:16px;}</style>"
                "</head><body><div class='card'>"
                "<h2>🛡️ Akses Ditangguhkan (Restricted Mode)</h2>"
                "<p>Lisensi komersial server SIMPATI 555 ini telah kedaluwarsa atau belum terverifikasi secara sah. "
                "Untuk melindungi integritas data, seluruh fitur pendaftaran baru, mutasi data, dan upload berkas ditangguhkan sementara.</p>"
                "<p>Akses baca data dan ekspor berkas cadangan tetap aktif.</p>"
                "<a href='/admin' class='btn'>Kembali ke Dashboard Admin</a>"
                "</div></body></html>"
            )
            return HTMLResponse(content=error_html, status_code=403)

        return await call_next(request)
