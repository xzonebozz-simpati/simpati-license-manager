"""User and session models for SIMPATI License Manager."""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Boolean, DateTime, Text, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin, utc_now


class LicenseUser(Base, UUIDMixin, TimestampMixin):
    """User account authorized to manage SIMPATI licenses."""
    __tablename__ = "license_users"

    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(100), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(30), default="SUPERADMIN", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    sessions: Mapped[List["LicenseUserSession"]] = relationship(
        "LicenseUserSession",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["LicenseAuditLog"]] = relationship(
        "LicenseAuditLog",
        back_populates="user"
    )


class LicenseUserSession(Base, UUIDMixin):
    """Active session tokens for License Manager users."""
    __tablename__ = "license_user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("license_users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    session_token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    user: Mapped["LicenseUser"] = relationship("LicenseUser", back_populates="sessions")
