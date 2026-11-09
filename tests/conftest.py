"""Pytest configuration and test fixtures."""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Force test configuration
os.environ["APP_ENV"] = "testing"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from app.models.base import Base
from app.database.session import get_db
from app.main import app
from scripts.init_db import seed_initial_data

# In-memory test engine with StaticPool to keep schema in memory across threads
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine
)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Creates database schema in memory and seeds initial data."""
    Base.metadata.create_all(bind=test_engine)
    # Seed data
    db = TestingSessionLocal()
    try:
        from app.models.user import LicenseUser
        from app.models.catalog import ModuleRegistry, LicensePackage
        from app.security.hashing import hash_password

        # Superadmin
        admin = LicenseUser(
            username="testadmin",
            email="testadmin@simpati.test",
            full_name="Test Superadmin",
            password_hash=hash_password("TestSecret@2026!"),
            role="SUPERADMIN",
            is_active=True
        )
        superadmin = LicenseUser(
            username="superadmin",
            email="superadmin@simpati555.id",
            full_name="SIMPATI License Superadmin",
            password_hash=hash_password("SuperAdmin@2026!"),
            role="SUPERADMIN",
            is_active=True
        )
        db.add_all([admin, superadmin])

        # Basic Modules Registry
        modules = [
            ModuleRegistry(module_code="CORE", module_name="Core Foundation", is_core=True),
            ModuleRegistry(module_code="DATA", module_name="Data Management", is_core=False),
            ModuleRegistry(module_code="SURVEI_GPS", module_name="Survei & GPS Mapping", is_core=False),
            ModuleRegistry(module_code="UMKM", module_name="Pemberdayaan UMKM", is_core=False),
            ModuleRegistry(module_code="REPORT_ADV", module_name="Advanced Reporting", is_core=False),
            ModuleRegistry(module_code="FINANCE", module_name="Keuangan & Anggaran", is_core=False),
            ModuleRegistry(module_code="COOP", module_name="Koperasi Organisasi", is_core=False),
            ModuleRegistry(module_code="SOCIAL", module_name="Bantuan Sosial", is_core=False),
            ModuleRegistry(module_code="ASSET", module_name="Inventaris Aset", is_core=False),
        ]
        db.add_all(modules)

        # Basic Package
        pkg = LicensePackage(package_code="PKG-TEST", package_name="Paket Test", default_tier="STANDARD")
        db.add(pkg)

        db.commit()
    finally:
        db.close()

    yield

    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    """Provides a fresh transactional database session for each test."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client(db_session):
    """Provides FastAPI TestClient with overridden database session."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
