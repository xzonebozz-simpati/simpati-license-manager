"""Customer (Client Organization) models for SIMPATI License Manager."""

from typing import Optional, List
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin


class Customer(Base, UUIDMixin, TimestampMixin):
    """Customer organization that holds rights to deploy SIMPATI."""
    __tablename__ = "customers"

    customer_code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    organization_name: Mapped[str] = mapped_column(String(150), nullable=False, index=True)
    contact_person: Mapped[str] = mapped_column(String(100), nullable=False)
    contact_email: Mapped[str] = mapped_column(String(120), nullable=False)
    contact_phone: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE", nullable=False)  # ACTIVE, SUSPENDED, TERMINATED
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    installations: Mapped[List["Installation"]] = relationship(
        "Installation",
        back_populates="customer",
        cascade="all, delete-orphan"
    )
    licenses: Mapped[List["License"]] = relationship(
        "License",
        back_populates="customer",
        cascade="all, delete-orphan"
    )
