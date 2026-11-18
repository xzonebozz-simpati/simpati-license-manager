"""Database initialization, table creation, and initial seeding script."""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import logging
import secrets
from datetime import datetime, timezone, timedelta
from app.database.connection import engine
from app.database.session import SessionLocal
from app.models.base import Base
from app.models.user import LicenseUser
from app.models.catalog import LicensePackage, ModuleRegistry, ModuleDependency, PackageModule
from app.models.customer import Customer
from app.models.installation import Installation, InstallationCredential
from app.models.license import License, LicenseCapacity, LicenseInstallation
from app.models.region import Region
from app.models.security import SigningKey
from app.config import get_settings
from app.models.operations import SystemSetting, LicenseAuditLog
from app.security.hashing import hash_password, verify_password
from app.services.license_service import get_root_public_key

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("simpati.scripts.init_db")
settings = get_settings()


def _log_signing_key_diagnostics() -> None:
    private_key = settings.ED25519_PRIVATE_KEY_PEM or ""
    public_key = settings.ED25519_PUBLIC_KEY_PEM or ""
    vault_path = Path(settings.SIGNING_KEY_VAULT_PATH)
    public_vault_path = vault_path.with_suffix(".pub")
    private_key_stripped = private_key.strip()
    public_key_stripped = public_key.strip()

    logger.warning(
        "Startup Ed25519 key diagnostic: "
        "private_env_present=%s private_env_length=%d private_env_pem_markers_ok=%s "
        "private_env_literal_newlines=%s public_env_present=%s public_env_length=%d "
        "public_env_pem_markers_ok=%s public_env_literal_newlines=%s "
        "vault_private_file_exists=%s vault_public_file_exists=%s",
        bool(private_key),
        len(private_key),
        private_key_stripped.startswith("-----BEGIN PRIVATE KEY-----")
        and private_key_stripped.endswith("-----END PRIVATE KEY-----"),
        r"\n" in private_key,
        bool(public_key),
        len(public_key),
        public_key_stripped.startswith("-----BEGIN PUBLIC KEY-----")
        and public_key_stripped.endswith("-----END PUBLIC KEY-----"),
        r"\n" in public_key,
        vault_path.is_file(),
        public_vault_path.is_file(),
    )


def seed_initial_data():
    """Seeds default modules, packages, administrative user, and settings if not present."""
    db = SessionLocal()
    try:
        # 1. Superadmin User (Configurable via Environment Variables for Staging/Production)
        admin_uname = settings.ADMIN_USERNAME
        superadmin = db.query(LicenseUser).filter(LicenseUser.username == admin_uname).first()
        if not superadmin:
            logger.info(f"Membuat akun default License Superadmin ({admin_uname})...")
            superadmin = LicenseUser(
                username=admin_uname,
                email=settings.ADMIN_EMAIL,
                full_name=settings.ADMIN_FULL_NAME,
                password_hash=hash_password(settings.ADMIN_PASSWORD),
                role="SUPERADMIN",
                is_active=True
            )
            db.add(superadmin)
            db.flush()
        if settings.is_production:
            for user in db.query(LicenseUser).all():
                if verify_password("SuperAdmin@2026!", user.password_hash):
                    if user.username == admin_uname:
                        user.password_hash = hash_password(settings.ADMIN_PASSWORD)
                    else:
                        user.is_active = False
                    for session in user.sessions:
                        if session.revoked_at is None:
                            session.revoked_at = datetime.now(timezone.utc)
                    logger.warning("Akun yang masih memakai password bootstrap lama dinonaktifkan/dirotasi.")

        # 2. Module Registry
        module_definitions = [
            ("CORE", "Core Platform SIMPATI", "Fondasi sistem inti, otentikasi, dan pengaturan", True),
            ("DATA", "Kependudukan & Anggota", "Pengelolaan basis data anggota organisasi dan KTP", False),
            ("SURVEI_GPS", "Survei Lapangan & GPS", "Pemetaan geolokasi, tracking GPS, dan validasi lapangan", False),
            ("UMKM", "Pemberdayaan UMKM", "Katalog binaan, verifikasi usaha, dan rekapitulasi bantuan", False),
            ("REPORT_ADV", "Pelaporan Lanjutan", "Analitik demografi, ekspor agregat, dan grafik kinerja", False),
            ("FINANCE", "Keuangan & Iuran", "Catatan iuran anggota, pembukuan kas, dan donasi", False),
            ("COOP", "Koperasi Anggota", "Simpan pinjam, sisa hasil usaha, dan unit usaha bersama", False),
            ("SOCIAL", "Bantuan Sosial", "Penyaluran logistik bantuan dan program kemanusiaan", False),
            ("ASSET", "Inventaris & Aset", "Pendataan aset fisik, kendaraan dinas, dan inventaris kantor", False),
        ]

        created_modules = {}
        for code, name, desc, is_core in module_definitions:
            mod = db.query(ModuleRegistry).filter(ModuleRegistry.module_code == code).first()
            if not mod:
                mod = ModuleRegistry(
                    module_code=code,
                    module_name=name,
                    description=desc,
                    is_core=is_core,
                    is_active=True
                )
                db.add(mod)
                db.flush()
            created_modules[code] = mod

        # 3. Module Dependencies
        dependencies_map = [
            ("SURVEI_GPS", "CORE"),
            ("SURVEI_GPS", "DATA"),
            ("UMKM", "CORE"),
            ("UMKM", "DATA"),
            ("REPORT_ADV", "CORE"),
            ("REPORT_ADV", "DATA"),
            ("FINANCE", "CORE"),
            ("COOP", "CORE"),
            ("COOP", "FINANCE"),
            ("SOCIAL", "CORE"),
            ("SOCIAL", "DATA"),
            ("ASSET", "CORE"),
        ]

        for mod_code, req_code in dependencies_map:
            if mod_code in created_modules and req_code in created_modules:
                mod_id = created_modules[mod_code].id
                req_id = created_modules[req_code].id
                dep_exists = db.query(ModuleDependency).filter(
                    ModuleDependency.module_id == mod_id,
                    ModuleDependency.required_module_id == req_id
                ).first()
                if not dep_exists:
                    db.add(ModuleDependency(module_id=mod_id, required_module_id=req_id))

        # 4. License Packages
        package_definitions = [
            ("PKG-STARTER", "Paket Pemula", "STANDARD", "Akses modul dasar CORE dan DATA anggota organisasi"),
            ("PKG-PROFESSIONAL", "Paket Profesional", "PREMIUM", "Modul CORE, DATA, SURVEI_GPS, UMKM, dan REPORT_ADV"),
            ("PKG-ENTERPRISE", "Paket Lengkap Nasional", "ENTERPRISE", "Seluruh modul aplikasi SIMPATI 555 tanpa batasan fitur"),
        ]

        created_packages = {}
        for code, name, tier, desc in package_definitions:
            pkg = db.query(LicensePackage).filter(LicensePackage.package_code == code).first()
            if not pkg:
                pkg = LicensePackage(
                    package_code=code,
                    package_name=name,
                    default_tier=tier,
                    description=desc,
                    is_active=True
                )
                db.add(pkg)
                db.flush()
            created_packages[code] = pkg

        # 5. Link Package Modules
        starter_mods = ["CORE", "DATA"]
        for m_code in starter_mods:
            if m_code in created_modules and "PKG-STARTER" in created_packages:
                link = db.query(PackageModule).filter(
                    PackageModule.package_id == created_packages["PKG-STARTER"].id,
                    PackageModule.module_id == created_modules[m_code].id
                ).first()
                if not link:
                    db.add(PackageModule(
                        package_id=created_packages["PKG-STARTER"].id,
                        module_id=created_modules[m_code].id,
                        is_mandatory=True
                    ))

        pro_mods = ["CORE", "DATA", "SURVEI_GPS", "UMKM", "REPORT_ADV"]
        for m_code in pro_mods:
            if m_code in created_modules and "PKG-PROFESSIONAL" in created_packages:
                link = db.query(PackageModule).filter(
                    PackageModule.package_id == created_packages["PKG-PROFESSIONAL"].id,
                    PackageModule.module_id == created_modules[m_code].id
                ).first()
                if not link:
                    db.add(PackageModule(
                        package_id=created_packages["PKG-PROFESSIONAL"].id,
                        module_id=created_modules[m_code].id,
                        is_mandatory=True
                    ))

        # 6. Indonesian Master Regions (National Master Sample)
        sample_regions = [
            ("32", "JAWA BARAT", "PROVINSI", None),
            ("31", "DKI JAKARTA", "PROVINSI", None),
            ("33", "JAWA TENGAH", "PROVINSI", None),
            ("35", "JAWA TIMUR", "PROVINSI", None),
        ]
        for r_code, r_name, r_lvl, r_parent in sample_regions:
            reg = db.query(Region).filter(Region.region_code == r_code).first()
            if not reg:
                db.add(Region(region_code=r_code, name=r_name, level=r_lvl, is_active=True))

        # 7. System Settings
        default_settings = [
            ("default_grace_period_days", "7", "INTEGER", "Durasi toleransi keterlambatan validasi (hari)"),
            ("token_validation_interval_hours", "24", "INTEGER", "Interval berkala verifikasi token (jam)"),
            ("allow_restricted_mode", "true", "BOOLEAN", "Izinkan akses terbatas read-only saat grace period terlampaui"),
            ("signing_key_identifier", "KEY-SIMPATI-ROOT-V1", "STRING", "ID kunci Ed25519 aktif yang menerbitkan sertifikat"),
        ]
        for key, val, dt, desc in default_settings:
            setting = db.query(SystemSetting).filter(SystemSetting.setting_key == key).first()
            if not setting:
                db.add(SystemSetting(
                    setting_key=key,
                    setting_value=val,
                    data_type=dt,
                    description=desc,
                    is_encrypted=False,
                    updated_by=superadmin.id if superadmin else None
                ))

        # 8. Cryptographic Signing Key Record
        signing_key_id = "KEY-SIMPATI-ROOT-V1"
        key_record = db.query(SigningKey).filter(SigningKey.key_identifier == signing_key_id).first()
        _log_signing_key_diagnostics()
        pub_pem = get_root_public_key()
        if not key_record:
            db.add(SigningKey(
                key_identifier=signing_key_id,
                algorithm="Ed25519",
                public_key_pem=pub_pem,
                key_vault_reference="vault:simpati-license-root-key",
                is_active=True
            ))
        else:
            key_record.public_key_pem = pub_pem

        if settings.is_production:
            legacy_demo_license = db.query(License).filter(
                License.license_key == "SMP-LIC-2026-A1B2-C3D4",
                License.deleted_at.is_(None),
            ).first()
            if legacy_demo_license:
                legacy_demo_license.deleted_at = datetime.now(timezone.utc)
                legacy_demo_license.status = "REVOKED"
                for link in legacy_demo_license.installations:
                    link.is_active = False

            legacy_demo_installation = db.query(Installation).filter(
                Installation.installation_code == "INST-2026-DPD-01",
            ).first()
            if legacy_demo_installation:
                legacy_demo_installation.status = "REVOKED"
                for credential in legacy_demo_installation.credentials:
                    credential.is_active = False
                    credential.revoked_at = datetime.now(timezone.utc)

            db.commit()
            logger.info("Data contoh dilewati dan lisensi demo lama dinonaktifkan di staging/production.")
            return

        # 9. Initial Customer, Installation, & Active Commercial License for local readiness
        cust = db.query(Customer).filter(Customer.customer_code == "CUST-2026-DPD-JABAR").first()
        if not cust:
            cust = Customer(
                customer_code="CUST-2026-DPD-JABAR",
                organization_name="Dewan Pimpinan Daerah SIMPATI Jawa Barat",
                contact_person="Ir. H. Budi Santoso, M.T.",
                contact_email="kontak@simpatijabar.id",
                contact_phone="+62 812-3456-7890",
                address="Jl. R.E. Martadinata No. 555, Bandung, Jawa Barat",
                status="ACTIVE",
                notes="Pelanggan Perdana SIMPATI Tingkat Provinsi"
            )
            db.add(cust)
            db.flush()

            # Installation
            inst = Installation(
                customer_id=cust.id,
                installation_code="INST-2026-DPD-01",
                name="Server Produksi Cloud DPD Jabar",
                server_domain="jabar.simpati555.id",
                server_ip="103.144.20.10",
                environment="PRODUCTION",
                status="ACTIVE",
                last_heartbeat_at=datetime.now(timezone.utc)
            )
            db.add(inst)
            db.flush()

            # License
            now = datetime.now(timezone.utc)
            lic = License(
                license_key="SMP-LIC-2026-A1B2-C3D4",
                customer_id=cust.id,
                package_id=created_packages["PKG-PROFESSIONAL"].id,
                license_type="COMMERCIAL",
                status="ACTIVE",
                valid_from=now - timedelta(days=10),
                valid_until=now + timedelta(days=355),
                grace_period_days=7,
                max_installations=1,
                snapshot_entitlements='{"modules": ["CORE", "DATA", "SURVEI_GPS", "UMKM", "REPORT_ADV"], "levels": ["DPD", "DPC"]}',
                notes="Lisensi Tahunan Komersial Resmi DPD Jawa Barat"
            )
            db.add(lic)
            db.flush()

            # Capacity
            db.add(LicenseCapacity(
                license_id=lic.id,
                max_members=100000,
                max_accounts=250,
                max_concurrent_users=30,
                max_storage_mb=40960
            ))

            # Audit Log
            db.add(LicenseAuditLog(
                user_id=superadmin.id if superadmin else None,
                action_category="SYSTEM",
                action_name="INITIAL_SEEDING",
                target_resource="system",
                details='{"status": "Fondasi SIMPATI License Manager berhasil diinisialisasi"}',
                status="SUCCESS"
            ))

        # 10. Auto-healing: Ensure initial seed installation & license are bound and have active credentials
        default_inst = db.query(Installation).filter(Installation.installation_code == "INST-2026-DPD-01").first()
        default_lic = db.query(License).filter(License.license_key == "SMP-LIC-2026-A1B2-C3D4").first()
        if default_inst and default_lic:
            binding_exists = db.query(LicenseInstallation).filter(
                LicenseInstallation.license_id == default_lic.id,
                LicenseInstallation.installation_id == default_inst.id
            ).first()
            if not binding_exists:
                db.add(LicenseInstallation(
                    license_id=default_lic.id,
                    installation_id=default_inst.id,
                    is_active=True,
                    activated_at=datetime.now(timezone.utc)
                ))
                logger.info("Auto-binding initial seed license SMP-LIC-2026-A1B2-C3D4 ke INST-2026-DPD-01.")

            cred_exists = db.query(InstallationCredential).filter(
                InstallationCredential.installation_id == default_inst.id,
                InstallationCredential.is_active == True
            ).first()
            if not cred_exists:
                cid = "CID-" + secrets.token_hex(8).upper()
                csec = secrets.token_urlsafe(32)
                db.add(InstallationCredential(
                    installation_id=default_inst.id,
                    client_id=cid,
                    client_secret_hash=hash_password(csec),
                    is_active=True
                ))
                logger.info(f"Auto-generated credentials for INST-2026-DPD-01: {cid}")

        db.commit()
        logger.info("Inisialisasi database dan seeding data awal berhasil.")
    except Exception as exc:
        db.rollback()
        logger.error(f"Gagal saat seeding database: {exc}")
        raise
    finally:
        db.close()


def main():
    """Initializes tables and seeds data."""
    print("Membuat seluruh tabel skema database...")
    Base.metadata.create_all(bind=engine)
    print("Menyemai data awal (Superadmin, Modul, Paket, Pengaturan)...")
    seed_initial_data()
    print("Database siap digunakan.")


if __name__ == "__main__":
    main()
