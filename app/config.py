"""Configuration module for SIMPATI License Manager.

Loads environment variables, validates configurations, and provides
centralized application settings for Local, Staging, and Production (Hostless + Supabase).
"""

import os
from functools import lru_cache
from typing import List, Optional
from pydantic import Field, AliasChoices, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings schema and loader."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Optional server-to-server credentials for SIMPATI Universal API.
    UNIVERSAL_API_SERVICE_ID: Optional[str] = None
    UNIVERSAL_API_SERVICE_SECRET: Optional[SecretStr] = Field(
        default=None,
        repr=False,
    )
    UNIVERSAL_API_SERVICE_PREVIOUS_SECRET: Optional[SecretStr] = Field(
        default=None,
        repr=False,
    )

    # General App Settings & Port Binding
    APP_ENV: str = "development"
    APP_NAME: str = "SIMPATI License Manager"
    APP_VERSION: str = "1.1.0"
    APP_DEBUG: bool = False
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = Field(
        default=8000,
        validation_alias=AliasChoices("PORT", "APP_PORT"),
        description="Application listening port (automatically set by Hostless via PORT)"
    )

    # Security & Tokens
    SECRET_KEY: str = Field(
        default="simpati-super-secret-key-change-in-production-min-32-chars",
        description="Secret key for JWT sessions and payload integrity"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    COOKIE_SECURE: Optional[bool] = None

    # Dedicated PostgreSQL Database Configuration (Supabase compatible)
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"
    DB_NAME: str = "simpati_license_db"
    DATABASE_URL: str = Field(
        default="sqlite:///./simpati_license.db",
        description="SQLAlchemy Database URL (PostgreSQL Supabase URL for Staging/Production, SQLite for Local Testing)"
    )

    # Database Connection Pool Settings
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 300  # Supabase idle timeout protection (5 minutes)

    # License Business Rules
    DEFAULT_GRACE_PERIOD_DAYS: int = 7
    TOKEN_VALIDATION_INTERVAL_HOURS: int = 24
    ALLOW_RESTRICTED_MODE: bool = True

    # Cryptographic Signing Keys (Ed25519)
    # Environment variable has priority over filesystem path (ideal for 12-factor cloud deployment)
    ED25519_PRIVATE_KEY_PEM: Optional[str] = Field(
        default=None,
        description="Root Ed25519 Private Key in PEM format (read from cloud secrets)"
    )
    ED25519_PUBLIC_KEY_PEM: Optional[str] = Field(
        default=None,
        description="Root Ed25519 Public Key in PEM format (optional, derived automatically if omitted)"
    )
    SIGNING_KEY_VAULT_PATH: str = "secrets/keys/simpati_ed25519_root.key"
    SIGNING_KEY_IDENTIFIER: str = "KEY-SIMPATI-ROOT-V1"

    # Default Superadmin Account Initializer
    ADMIN_USERNAME: str = Field(default="superadmin", description="Initial Superadmin username")
    ADMIN_PASSWORD: str = Field(default="SuperAdmin@2026!", description="Initial Superadmin password")
    ADMIN_EMAIL: str = Field(default="superadmin@simpati555.id", description="Initial Superadmin email")
    ADMIN_FULL_NAME: str = Field(default="SIMPATI License Superadmin", description="Superadmin full name")

    # Reverse Proxy & Cloud Networking
    FORWARDED_ALLOW_IPS: str = Field(default="*", description="Trusted reverse proxy IP list for Hostless")
    CORS_ORIGINS: str = "http://localhost:8000,http://127.0.0.1:8000"

    @property
    def normalized_database_url(self) -> str:
        """Normalize PostgreSQL URL to use psycopg v3."""
        url = self.DATABASE_URL.strip()

        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)

        if url.startswith("postgresql://"):
            url = url.replace(
                "postgresql://",
                "postgresql+psycopg://",
                1
            )

        return url

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins string into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        """Check if running in staging or production mode."""
        return self.APP_ENV.lower() in ("production", "staging")

    @property
    def effective_cookie_secure(self) -> bool:
        """Cookie secure flag: True on production/staging HTTPS, False on local dev."""
        if self.COOKIE_SECURE is not None:
            return self.COOKIE_SECURE
        return self.is_production


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
