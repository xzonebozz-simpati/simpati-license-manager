"""Customer organization request and response schemas."""

from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class CustomerCreate(BaseModel):
    """Payload to create a new customer organization."""
    customer_code: str = Field(..., min_length=3, max_length=50)
    organization_name: str = Field(..., min_length=3, max_length=150)
    contact_person: str = Field(..., min_length=3, max_length=100)
    contact_email: EmailStr
    contact_phone: Optional[str] = Field(None, max_length=30)
    address: Optional[str] = None
    notes: Optional[str] = None


class CustomerUpdate(BaseModel):
    """Payload to update an existing customer."""
    organization_name: Optional[str] = None
    contact_person: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    address: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None


class CustomerStatusUpdate(BaseModel):
    """Payload to activate or suspend a customer."""
    status: str = Field(..., pattern="^(ACTIVE|SUSPENDED|TERMINATED)$")
    reason: Optional[str] = None


class CustomerInstallationSummary(BaseModel):
    """Summary of installation belonging to customer."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    installation_code: str
    name: str
    server_domain: Optional[str] = None
    server_ip: Optional[str] = None
    environment: str
    status: str
    last_heartbeat_at: Optional[datetime] = None


class CustomerLicenseSummary(BaseModel):
    """Summary of license belonging to customer."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    license_key: str
    package_name: str
    license_type: str
    status: str
    valid_from: datetime
    valid_until: datetime
    grace_period_days: int


class CustomerResponse(BaseModel):
    """Customer data representation schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    customer_code: str
    organization_name: str
    contact_person: str
    contact_email: str
    contact_phone: Optional[str] = None
    address: Optional[str] = None
    status: str
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CustomerDetailResponse(CustomerResponse):
    """Rich customer detail representation with relation summaries."""
    total_installations: int = 0
    active_installations: int = 0
    total_licenses: int = 0
    active_licenses: int = 0
    installations: List[CustomerInstallationSummary] = []
    licenses: List[CustomerLicenseSummary] = []
