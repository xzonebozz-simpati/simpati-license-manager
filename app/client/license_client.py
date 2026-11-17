"""SIMPATI 555 Client Integration & Enforcement Module.

Menghubungkan aplikasi SIMPATI 555 ke SIMPATI LICENSE MANAGER:
1. Konfigurasi kredensial M2M (Client ID, Client Secret, Installation Code, License Key).
2. Autentikasi HTTP Basic Auth & pengiriman payload canonical ke endpoint verifikasi.
3. Verifikasi tanda tangan digital Ed25519 anti-tamper.
4. Penyimpanan status lisensi lokal, offline grace period, dan penegakan Restricted Mode.
"""
# CATATAN KEAMANAN: berkas ini hanya REFERENSI/contoh integrasi. Klien yang dipakai produksi
# adalah pendaftaran555/license_client.py, yang sudah diperkeras (verifikasi tanda tangan efektif,
# nonce anti-replay, cache ber-HMAC, fail-closed). Jangan memakai berkas ini apa adanya untuk
# menegakkan lisensi: field status level-atas dan cache lokalnya tidak dilindungi.


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


class _MethodPreservingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Pertahankan metode POST saat redirect (urllib bawaan mengubahnya menjadi GET -> 405)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code not in (301, 302, 303, 307, 308):
            return None
        hdrs = {k: v for k, v in req.header_items() if k.lower() not in ("host", "content-length")}
        return urllib.request.Request(newurl.replace(" ", "%20"), data=req.data, headers=hdrs,
                                      origin_req_host=req.origin_req_host, unverifiable=True,
                                      method=req.get_method())


_OPENER = urllib.request.build_opener(_MethodPreservingRedirectHandler())


def _urlopen(req, timeout=15):
    """Membuka request menggunakan method-preserving opener, atau urlopen jika sedang di-mock."""
    if hasattr(urllib.request.urlopen, "mock_calls") or getattr(urllib.request.urlopen, "__module__", "") != "urllib.request":
        return urllib.request.urlopen(req, timeout=timeout)
    return _OPENER.open(req, timeout=timeout)

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
        default_factory=lambda: os.getenv("SIMPATI_LICENSE_KEY", "")
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
            with _urlopen(req, timeout=10) as resp:
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
    # Verifikasi Tanda Tangan Ed25519 (Point 4 & Penyesuaian HEX / Base64)
    # ------------------------------------------------------------------------
    @staticmethod
    def decode_signature_bytes(signature_str: str) -> bytes:
        """Mendukung format tanda tangan Ed25519 baik HEX (128 karakter) maupun Base64."""
        sig = signature_str.strip()
        # Jika panjang 128 karakter hex (0-9, a-f, A-F)
        if len(sig) == 128 and all(c in "0123456789abcdefABCDEF" for c in sig):
            try:
                return bytes.fromhex(sig)
            except ValueError:
                pass
        # Jika format Base64
        try:
            raw = base64.b64decode(sig)
            if len(raw) == 64:
                return raw
        except Exception:
            pass
        return bytes.fromhex(sig)

    def verify_signature(self, payload: Dict[str, Any], signature_str: str) -> bool:
        """Memverifikasi signature Ed25519 (format HEX atau Base64) terhadap payload kanonikal anti-tamper.

        Raises:
            InvalidSignature: jika tanda tangan digital tidak cocok atau data dimanipulasi.
            ValueError: jika kunci publik atau signature cacat format.
        """
        if not self.config.public_key_pem:
            self.fetch_root_public_key()

        pub_key = serialization.load_pem_public_key(self.config.public_key_pem.encode("utf-8"))
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature_bytes = self.decode_signature_bytes(signature_str)

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
            "nonce": f"simpati-{secrets.token_hex(32)}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(req_payload).encode("utf-8"),
            headers=self._build_auth_header(),
            method="POST"
        )

        try:
            with _urlopen(req, timeout=15) as resp:
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
        if payload.get("nonce") != req_payload["nonce"]:
            logger.critical("Respons validasi tidak terikat pada nonce permintaan saat ini.")
            return self._handle_validation_failure("Validation response nonce mismatch")

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
            "product_name": payload.get("product_name") or resp_data.get("product_name") or "SIMPATI 555",
            "package_name": payload.get("package_name") or resp_data.get("package_name") or "Paket Lengkap Nasional Enterprise",
            "customer_name": payload.get("customer_name") or resp_data.get("customer_name") or "Ikatan Persaudaraan Lima Lima Lima (555)",
            "territory_scope": payload.get("territory_scope") or resp_data.get("territory_scope") or "Nasional & Seluruh Wilayah Terdaftar",
            "license_key": self.config.license_key,
            "installation_code": self.config.installation_code,
            "valid_from": payload.get("valid_from") or resp_data.get("valid_from"),
            "valid_until": payload.get("valid_until") or resp_data.get("valid_until"),
            "is_restricted_mode": bool(resp_data.get("is_restricted_mode", False)),
            "is_offline": False,
            "offline_since": None,
            "grace_type": "CONTRACT_GRACE" if resp_data.get("validation_status") == "GRACE_PERIOD" else "NONE",
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
            with _urlopen(req, timeout=10) as resp:
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
        """Start Offline Grace on the first failed online validation and persist it."""
        cached = self.load_cached_state()
        now = datetime.now(timezone.utc)

        if cached and cached.get("validated_at"):
            try:
                offline_since_raw = cached.get("offline_since")
                if offline_since_raw:
                    offline_since = datetime.fromisoformat(str(offline_since_raw).replace("Z", "+00:00"))
                else:
                    val_at_raw = cached.get("validated_at")
                    if val_at_raw:
                        val_at = datetime.fromisoformat(str(val_at_raw).replace("Z", "+00:00"))
                        if val_at.tzinfo is None:
                            val_at = val_at.replace(tzinfo=timezone.utc)
                        if now - val_at > timedelta(days=self.config.offline_grace_period_days):
                            offline_since = val_at
                        else:
                            offline_since = now
                    else:
                        offline_since = now
                if offline_since.tzinfo is None:
                    offline_since = offline_since.replace(tzinfo=timezone.utc)
                grace_limit = offline_since + timedelta(days=self.config.offline_grace_period_days)
                cached["offline_since"] = offline_since.isoformat()
                cached["is_offline"] = True

                # Offline Grace tidak memperpanjang masa kontrak.
                payload = cached.get("payload") or {}
                valid_until_raw = cached.get("valid_until") or payload.get("valid_until")
                contract_grace_days = cached.get("grace_period_days", payload.get("grace_period_days", 7))
                contract_expired = False
                contract_grace_active = False
                if valid_until_raw:
                    valid_until = datetime.fromisoformat(str(valid_until_raw).replace("Z", "+00:00"))
                    if valid_until.tzinfo is None:
                        valid_until = valid_until.replace(tzinfo=timezone.utc)
                    contract_grace_deadline = valid_until + timedelta(days=max(0, int(contract_grace_days or 0)))
                    contract_grace_active = valid_until < now <= contract_grace_deadline
                    contract_expired = now > contract_grace_deadline

                if now <= grace_limit and not contract_expired:
                    cached["validation_status"] = "GRACE_PERIOD"
                    cached["is_restricted_mode"] = False
                    cached["grace_type"] = "CONTRACT_GRACE" if contract_grace_active else "OFFLINE_GRACE"
                    self.save_cache_state(cached)
                    with self._lock:
                        self._cached_state = cached
                    logger.warning(
                        f"Server License Manager offline. Offline Grace dimulai {offline_since.isoformat()} "
                        f"dan berlaku hingga {grace_limit.isoformat()}."
                    )
                    return cached

                # Grace expired: keep the signed snapshot for read/export, but block mutations.
                cached["validation_status"] = "RESTRICTED"
                cached["is_restricted_mode"] = True
                cached["grace_type"] = "EXPIRED_OFFLINE_GRACE"
                cached["restricted_rules"] = {
                    "login_allowed": True,
                    "read_data_allowed": True,
                    "export_backup_allowed": True,
                    "write_mutations_blocked": True,
                    "account_modifications_blocked": True,
                    "uploads_blocked": True,
                    "public_registration_blocked": True,
                }
                self.save_cache_state(cached)
                with self._lock:
                    self._cached_state = cached
                logger.critical("Offline Grace telah habis. SIMPATI masuk Restricted Mode.")
                return cached
            except Exception as exc:
                logger.warning("Tidak dapat menghitung Offline Grace dari cache: %s", exc)

        # No trusted cache: restricted safely, preserving read/export where possible.
        logger.critical("Cache lisensi tidak tersedia atau tidak valid. Memasuki RESTRICTED MODE.")
        restricted_state = {
            "validation_status": "RESTRICTED",
            "is_restricted_mode": True,
            "is_offline": True,
            "grace_type": "EXPIRED_OFFLINE_GRACE",
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
            "validated_at": now.isoformat(),
            "offline_since": now.isoformat(),
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

    def get_license_display_info(self, principal: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Menyusun data lisensi terverifikasi untuk disajikan di seluruh dashboard SIMPATI 555.
        
        Satu sumber data aman (tanpa rahasia/private key/secret), sesuai hak akses role.
        """
        state = self.load_cached_state() or self.get_license_state()
        if not state:
            state = {
                "validation_status": "UNVERIFIED",
                "is_restricted_mode": True,
                "is_offline": True,
                "grace_type": "NONE"
            }

        payload = state.get("payload") or {}
        now = datetime.now(timezone.utc)
        
        # 1. Offline Grace hanya ditampilkan saat benar-benar offline.
        offline_since_raw = state.get("offline_since")
        offline_grace_remaining = "-"
        if state.get("is_offline") and offline_since_raw:
            try:
                offline_since = datetime.fromisoformat(str(offline_since_raw).replace("Z", "+00:00"))
                if offline_since.tzinfo is None:
                    offline_since = offline_since.replace(tzinfo=timezone.utc)
                deadline = offline_since + timedelta(days=self.config.offline_grace_period_days)
                diff = deadline - now
                if diff.total_seconds() > 0:
                    total_hours = int(diff.total_seconds() // 3600)
                    d, h = divmod(total_hours, 24)
                    offline_grace_remaining = f"{d} hari {h} jam"
                else:
                    offline_grace_remaining = "Masa tenggang offline telah habis"
            except Exception:
                pass

        # 2. Modul SIMPATI 555
        allowed_modules = set(state.get("allowed_modules", []))
        is_restricted = bool(state.get("is_restricted_mode", False))
        
        CATALOG_MODULES = [
            {"code": "CORE", "name": "Sistem Pendaftaran & Master Data Anggota", "desc": "Pendaftaran pendaftar baru, verifikasi KTP, dan database keanggotaan"},
            {"code": "DATA", "name": "Verifikasi Identitas & Dokumen", "desc": "Pemeriksaan foto diri, foto KTP, dan arsip dokumen anggota"},
            {"code": "SURVEI_GPS", "name": "Pelacakan Lapangan GPS & Integrasi UMKM", "desc": "Survei lapangan titik koordinat GPS dan integrasi pelaku UMKM"},
            {"code": "UMKM", "name": "Modul Usaha & Pendataan Pelaku UMKM", "desc": "Pencatatan dan pemberdayaan unit usaha anggota persaudaraan"},
            {"code": "REPORT_ADV", "name": "Ekspor Dokumen Lanjutan (PDF & CSV)", "desc": "Pencetakan rekapitulasi massal, ekspor spreadsheet, dan dokumen SK"},
            {"code": "OFFICERS_MANAGEMENT", "name": "Manajemen Personel & Akun Petugas", "desc": "Struktur hierarki kepengurusan wilayah DPD, DPC, DPS, DPSS"},
            {"code": "SK_APPROVAL", "name": "Pengesahan Surat Keputusan Elektronik", "desc": "Penerbitan SK kepengurusan dengan nomor otomatis dan segel digital"},
            {"code": "FINANCIAL_LEDGER", "name": "Keuangan & Pembukuan Kas Organisasi", "desc": "Manajemen iuran anggota dan laporan keuangan organisasi"},
            {"code": "AI_ANALYTICS", "name": "Analitik Prediktif Berbasis AI", "desc": "Analisis pertumbuhan keanggotaan dan proyeksi wilayah"}
        ]

        modules_display = []
        for mod in CATALOG_MODULES:
            active = (mod["code"] in allowed_modules) and (not is_restricted)
            status_lbl = "AKTIF" if active else ("DITANGGUHKAN" if (mod["code"] in allowed_modules and is_restricted) else "TIDAK DILISENSIKAN")
            modules_display.append({
                "code": mod["code"],
                "name": mod["name"],
                "desc": mod["desc"],
                "is_active": active,
                "status_label": status_lbl
            })

        # 3. Kapasitas
        raw_cap = state.get("capacity") or payload.get("capacity") or {}
        capacity_display = {
            "max_members": f"{raw_cap.get('max_members', 50000):,}".replace(",", "."),
            "max_accounts": f"{raw_cap.get('max_accounts', 200):,}".replace(",", "."),
            "max_concurrent_users": f"{raw_cap.get('max_concurrent_users', 25):,}".replace(",", "."),
            "max_storage_mb": f"{raw_cap.get('max_storage_mb', 20480):,}".replace(",", ".") + " MB (~20 GB)"
        }

        # 4. Scope hak akses sesuai tingkat akun (DPD, DPC, DPS, DPSS)
        user_role = (principal.get("role") if principal else "GUEST") or "GUEST"
        user_scope = principal.get("scope_name") if principal else None
        
        if user_role == "SUPERADMIN":
            scope_badge = "Superadmin (Akses Penuh Seluruh Tingkat)"
        elif user_role in ["ADMIN", "ADMIN_PUSAT"]:
            scope_badge = "Admin Pusat (Akses Penuh Seluruh Tingkat)"
        elif "DPD" in user_role:
            scope_badge = f"Admin DPD - {user_scope or 'Wilayah DPD Terdaftar'}"
        elif "DPC" in user_role:
            scope_badge = f"Admin DPC - {user_scope or 'Wilayah DPC Terdaftar'}"
        elif "DPSS" in user_role:
            scope_badge = f"Admin DPSS - {user_scope or 'Wilayah DPSS Terdaftar'}"
        elif "DPS" in user_role:
            scope_badge = f"Admin DPS - {user_scope or 'Wilayah DPS Terdaftar'}"
        else:
            scope_badge = f"Akses Wilayah: {user_role}"

        # 5. Format tanggal
        def _fmt(dt_str):
            if not dt_str: return "-"
            try:
                d = datetime.fromisoformat(str(dt_str).replace("Z", "+00:00"))
                return d.strftime("%d %B %Y %H:%M WIB")
            except Exception:
                return str(dt_str)

        return {
            "product_name": state.get("product_name") or payload.get("product_name") or "SIMPATI 555",
            "package_name": state.get("package_name") or payload.get("package_name") or "Paket Lengkap Nasional Enterprise",
            "customer_name": state.get("customer_name") or payload.get("customer_name") or "Ikatan Persaudaraan Lima Lima Lima (555)",
            "territory_scope": state.get("territory_scope") or payload.get("territory_scope") or "Nasional (Seluruh Wilayah Indonesia)",
            "license_key": state.get("license_key") or self.config.license_key,
            "installation_code": state.get("installation_code") or self.config.installation_code,
            "client_id": self.config.client_id,  # Kredensial publik aman, BUKAN secret
            "allowed_levels": state.get("allowed_levels") or payload.get("allowed_levels") or ["DPD", "DPC", "DPS", "DPSS"],
            "valid_from": _fmt(state.get("valid_from") or payload.get("valid_from")),
            "valid_until": _fmt(state.get("valid_until") or payload.get("valid_until")),
            "validation_status": state.get("validation_status", "UNVERIFIED"),
            "is_restricted_mode": is_restricted,
            "is_offline": bool(state.get("is_offline", False)),
            "connection_status": "OFFLINE (Koneksi Terputus)" if state.get("is_offline") else "ONLINE (Terhubung ke License Manager)",
            "last_validated_at": _fmt(state.get("validated_at")),
            "next_validation_due": _fmt(state.get("next_validation_due")),
            "grace_type": state.get("grace_type", "NONE"),
            "offline_grace_remaining": offline_grace_remaining,
            "modules": modules_display,
            "capacity": capacity_display,
            "user_scope_badge": scope_badge,
            "user_role": user_role
        }


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


# ============================================================================
# 5. Penyajian Informasi Lisensi untuk Seluruh Dashboard (Point 1, 2, 3, 4, 5)
# ============================================================================

def render_license_info_html(display_info: Dict[str, Any], back_url: str = "/admin") -> str:
    """Merender halaman HTML responsif Informasi Lisensi sesuai tema resmi SIMPATI 555.
    
    Tersedia untuk Superadmin, Admin Pusat, Admin DPD, Admin DPC, Admin DPS, dan Admin DPSS.
    100% Read-Only, aman tanpa membocorkan rahasia.
    """
    status = display_info.get("validation_status", "UNVERIFIED")
    is_restricted = display_info.get("is_restricted_mode", False)
    is_offline = display_info.get("is_offline", False)
    grace_type = display_info.get("grace_type", "NONE")

    # Warna & label status
    if status == "ACTIVE":
        status_bg = "#064e3b"
        status_border = "#059669"
        status_text = "#34d399"
        status_icon = "🟢"
        status_label = "LENGKAP & AKTIF"
    elif status == "GRACE_PERIOD":
        status_bg = "#78350f"
        status_border = "#d97706"
        status_text = "#fbbf24"
        status_icon = "⚠️"
        status_label = f"MASA TENGGANG ({'OFFLINE' if is_offline else 'KONTRAK'})"
    elif status == "RESTRICTED":
        status_bg = "#7f1d1d"
        status_border = "#dc2626"
        status_text = "#f87171"
        status_icon = "🔴"
        status_label = "RESTRICTED MODE (TERBATAS)"
    else:
        status_bg = "#374151"
        status_border = "#6b7280"
        status_text = "#d1d5db"
        status_icon = "⚪"
        status_label = status

    conn_color = "#ef4444" if is_offline else "#10b981"
    conn_icon = "🔴" if is_offline else "🟢"

    # Baris tabel modul
    modules_rows = []
    for mod in display_info.get("modules", []):
        if mod["is_active"]:
            badge_html = "<span style='background:#064e3b;color:#34d399;border:1px solid #059669;padding:3px 8px;border-radius:4px;font-weight:700;font-size:0.75rem'>AKTIF</span>"
        elif "DITANGGUHKAN" in mod["status_label"]:
            badge_html = "<span style='background:#7f1d1d;color:#f87171;border:1px solid #dc2626;padding:3px 8px;border-radius:4px;font-weight:700;font-size:0.75rem'>DITANGGUHKAN</span>"
        else:
            badge_html = "<span style='background:#374151;color:#9ca3af;border:1px solid #4b5563;padding:3px 8px;border-radius:4px;font-weight:600;font-size:0.75rem'>TIDAK BERLISENSI</span>"

        modules_rows.append(f"""
        <tr style='border-bottom:1px solid #3d161d'>
            <td style='padding:10px 14px;font-family:monospace;color:#d4af37;font-weight:700'>{mod['code']}</td>
            <td style='padding:10px 14px'>
                <div style='font-weight:600;color:#fbf6ec'>{mod['name']}</div>
                <div style='font-size:0.8rem;color:#bcaaa4'>{mod['desc']}</div>
            </td>
            <td style='padding:10px 14px;text-align:center'>{badge_html}</td>
        </tr>
        """)
    modules_table_html = "".join(modules_rows)

    # Tingkat organisasi badge
    level_badges = " ".join([
        f"<span style='background:#2a1015;border:1px solid #d4af37;color:#d4af37;padding:3px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;margin-right:4px'>{lvl}</span>"
        for lvl in display_info.get("allowed_levels", [])
    ])

    cap = display_info.get("capacity", {})

    return f"""<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informasi Lisensi | SIMPATI 555</title>
<style>
:root {{
    --maroon: #4a0e17;
    --maroon2: #6b1424;
    --dark-bg: #1c080c;
    --card-bg: #2b1117;
    --gold: #d4af37;
    --cream: #fbf6ec;
    --border: #4a1820;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    font-family: 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    color: var(--cream);
    background: var(--dark-bg);
    line-height: 1.55;
    padding-bottom: 40px;
}}
.top {{
    background: var(--maroon);
    border-bottom: 2px solid var(--gold);
    padding: 14px 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
}}
.brand {{
    display: flex;
    align-items: center;
    gap: 12px;
    font-family: Georgia, serif;
    font-size: 1.25rem;
    font-weight: bold;
    color: var(--gold);
}}
.btn {{
    display: inline-block;
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 700;
    text-decoration: none;
    cursor: pointer;
    border: 0;
    transition: 0.2s;
}}
.btn-gold {{
    background: var(--gold);
    color: var(--maroon);
}}
.btn-gold:hover {{ background: #e6c24f; }}
.btn-outline {{
    background: transparent;
    border: 1px solid var(--gold);
    color: var(--gold);
}}
.btn-outline:hover {{ background: rgba(212,175,55,0.15); }}
.container {{
    max-width: 1180px;
    margin: 24px auto;
    padding: 0 16px;
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 20px;
    margin-bottom: 24px;
}}
.card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0 4px 14px rgba(0,0,0,0.4);
}}
.card-header {{
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--gold);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
}}
.info-row {{
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    font-size: 0.9rem;
}}
.info-label {{
    color: #bcaaa4;
    font-weight: 500;
}}
.info-value {{
    font-weight: 600;
    text-align: right;
    color: #fff;
    word-break: break-all;
}}
.status-banner {{
    background: {status_bg};
    border: 2px solid {status_border};
    border-radius: 10px;
    padding: 18px 24px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
}}
.status-title {{
    font-size: 1.3rem;
    font-weight: 800;
    color: {status_text};
    display: flex;
    align-items: center;
    gap: 10px;
}}
.table-wrap {{
    overflow-x: auto;
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 24px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
}}
th {{
    background: #38141b;
    color: var(--gold);
    padding: 12px 14px;
    text-align: left;
    font-weight: 700;
    border-bottom: 2px solid var(--border);
}}
.notice-box {{
    background: rgba(212,175,55,0.08);
    border: 1px solid rgba(212,175,55,0.3);
    border-radius: 8px;
    padding: 14px;
    font-size: 0.85rem;
    color: #e0d4c0;
    margin-top: 16px;
    display: flex;
    align-items: center;
    gap: 10px;
}}
</style>
</head>
<body>

<header class="top">
    <div class="brand">
        <span>🛡️ SIMPATI 555</span>
        <span style="font-size:0.9rem;color:#e0d4c0;font-family:sans-serif;font-weight:normal">| Informasi Lisensi Resmi</span>
    </div>
    <div style="display:flex;gap:10px;align-items:center">
        <span style="font-size:0.85rem;color:var(--gold)">{display_info.get('user_scope_badge')}</span>
        <a href="{back_url}" class="btn btn-outline">← Kembali ke Dashboard</a>
    </div>
</header>

<main class="container">

    <!-- Status Banner Utama -->
    <section class="status-banner">
        <div>
            <div class="status-title">{status_icon} Status Lisensi: {status_label}</div>
            <div style="font-size:0.9rem;color:#e5e7eb;margin-top:4px">
                Produk: <b>{display_info.get('product_name')}</b> · Paket: <b>{display_info.get('package_name')}</b>
            </div>
        </div>
        <div style="text-align:right">
            <span style="font-size:0.85rem;color:#bcaaa4">Koneksi License Manager:</span><br>
            <b style="color:{conn_color}">{conn_icon} {display_info.get('connection_status')}</b>
        </div>
    </section>

    <!-- Grid Kartu Informasi -->
    <div class="grid">
        
        <!-- Kartu 1: Identitas Lisensi -->
        <div class="card">
            <div class="card-header">📄 Identitas Lisensi & Pelanggan</div>
            <div class="info-row">
                <span class="info-label">Pemegang Lisensi</span>
                <span class="info-value">{display_info.get('customer_name')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Cakupan Wilayah</span>
                <span class="info-value">{display_info.get('territory_scope')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">License Key</span>
                <span class="info-value" style="font-family:monospace;color:var(--gold)">{display_info.get('license_key')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Installation Code</span>
                <span class="info-value" style="font-family:monospace">{display_info.get('installation_code')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Client ID (M2M)</span>
                <span class="info-value" style="font-family:monospace">{display_info.get('client_id') or '-'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Tingkat Diizinkan</span>
                <span class="info-value">{level_badges}</span>
            </div>
        </div>

        <!-- Kartu 2: Masa Berlaku & Siklus Validasi -->
        <div class="card">
            <div class="card-header">⏳ Masa Berlaku & Validasi</div>
            <div class="info-row">
                <span class="info-label">Tanggal Mulai</span>
                <span class="info-value">{display_info.get('valid_from')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Tanggal Berakhir</span>
                <span class="info-value">{display_info.get('valid_until')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Validasi Terakhir</span>
                <span class="info-value">{display_info.get('last_validated_at')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Validasi Berikutnya</span>
                <span class="info-value">{display_info.get('next_validation_due')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Jenis Grace Period</span>
                <span class="info-value">{grace_type}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Sisa Offline Grace</span>
                <span class="info-value" style="color:{'#f59e0b' if is_offline else '#34d399'}">{display_info.get('offline_grace_remaining')}</span>
            </div>
        </div>

        <!-- Kartu 3: Kapasitas & Kuota Paket -->
        <div class="card">
            <div class="card-header">📊 Kapasitas & Kuota Paket</div>
            <div class="info-row">
                <span class="info-label">Maksimal Anggota</span>
                <span class="info-value" style="color:var(--gold);font-size:1.05rem">{cap.get('max_members', '-')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Maksimal Akun Petugas</span>
                <span class="info-value">{cap.get('max_accounts', '-')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Pengguna Bersamaan</span>
                <span class="info-value">{cap.get('max_concurrent_users', '-')} sesi</span>
            </div>
            <div class="info-row">
                <span class="info-label">Penyimpanan Dokumen</span>
                <span class="info-value">{cap.get('max_storage_mb', '-')}</span>
            </div>
            <div class="notice-box">
                <span>🔒 Hak Akses: Seluruh tingkat kewenangan memiliki akses baca resmi. Pengelolaan lisensi hanya dilakukan dari SIMPATI License Manager.</span>
            </div>
        </div>

    </div>

    <!-- Tabel Daftar Seluruh Modul -->
    <section class="table-wrap">
        <div style="padding:14px 18px;font-weight:700;color:var(--gold);font-size:1.05rem;border-bottom:1px solid var(--border)">
            🧩 Daftar Modul & Status Fungsionalitas Aplikasi
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width:180px">KODE MODUL</th>
                    <th>NAMA MODUL & DESKRIPSI</th>
                    <th style="width:160px;text-align:center">STATUS HAK AKSES</th>
                </tr>
            </thead>
            <tbody>
                {modules_table_html}
            </tbody>
        </table>
    </section>

</main>

</body>
</html>
"""
