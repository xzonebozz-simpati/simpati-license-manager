"""Configuration module for SIMPATI License Manager.

Loads environment variables, validates configurations, and provides
centralized application settings.
"""

from functools import lru_cache
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings schema and loader."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # General App Settings
    APP_ENV: str = "development"
    APP_NAME: str = "SIMPATI License Manager"
    APP_VERSION: str = "1.0.0"
    APP_DEBUG: bool = True
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    # Security & Tokens
    SECRET_KEY: str = Field(
        default="simpati-super-secret-key-change-in-production-min-32-chars",
        description="Secret key for JWT sessions and payload integrity"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    # Dedicated PostgreSQL Database Configuration
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"
    DB_NAME: str = "simpati_license_db"
    DATABASE_URL: str = Field(
        default="sqlite:///./simpati_license.db",
        description="SQLAlchemy Database URL (PostgreSQL for Production, SQLite for Local Testing)"
    )

    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    # License Business Rules
    DEFAULT_GRACE_PERIOD_DAYS: int = 7
    TOKEN_VALIDATION_INTERVAL_HOURS: int = 24
    ALLOW_RESTRICTED_MODE: bool = True

    # Cryptographic Signing Keys
    SIGNING_KEY_VAULT_PATH: str = "secrets/keys/simpati_ed25519_root.key"
    SIGNING_KEY_IDENTIFIER: str = "KEY-SIMPATI-ROOT-V1"

    # CORS
    CORS_ORIGINS: str = "http://localhost:8000,http://127.0.0.1:8000"

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins string into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.APP_ENV.lower() == "production"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
