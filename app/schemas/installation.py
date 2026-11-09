"""Installation identity, lifecycle, and telemetry schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

class InstallationCreate(BaseModel):
    """Payload to register a new SIMPATI installation under a customer."""
    customer_id: UUID
    installation_code: Optional[str] = Field(None, min_length=3, max_length=60)
    name: str = Field(..., min_length=3, max_length=120)
    server_domain: Optional[str] = None
    server_ip: Optional[str] = None
    environment: str = Field(default="PRODUCTION")
    public_key_pem: Optional[str] = None
    hardware_signature: Optional[str] = None


class InstallationRegister(InstallationCreate):
    """Alias for backwards compatibility with earlier iteration."""
    pass


class InstallationUpdate(BaseModel):
    """Payload to update an existing installation."""
    name: Optional[str] = Field(None, min_length=3, max_length=120)
    server_domain: Optional[str] = None
    server_ip: Optional[str] = None
    environment: Optional[str] = None
    public_key_pem: Optional[str] = None
    hardware_signature: Optional[str] = None


class InstallationStatusUpdate(BaseModel):
    """Payload to change operational status."""
    status: str = Field(..., pattern="^(ACTIVE|SUSPENDED|REVOKED)$")
    reason: Optional[str] = None


class InstallationPublicKeyRegister(BaseModel):
    """Payload to register or replace Ed25519 public key."""
    public_key_pem: str = Field(..., min_length=20)


class InstallationHeartbeat(BaseModel):
    """Heartbeat telemetry ping sent periodically from an installation."""
    installation_code: str
    client_id: Optional[str] = None
    current_version: str = "555.2.0"
    active_user_count: int = 0
    total_members_recorded: int = 0
    status_summary: str = "HEALTHY"


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

class InstallationCredentialResponse(BaseModel):
    """API credential metadata."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    client_id: str
    is_active: bool
    created_at: datetime
    revoked_at: Optional[datetime] = None


class InstallationEventResponse(BaseModel):
    """Installation telemetry and lifecycle event log."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    event_type: str
    payload: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    recorded_at: datetime


class InstallationResponse(BaseModel):
    """Installation summary response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    customer_id: UUID
    installation_code: str
    name: str
    server_domain: Optional[str] = None
    server_ip: Optional[str] = None
    environment: str
    status: str
    hardware_signature: Optional[str] = None
    public_key_pem: Optional[str] = None
    last_heartbeat_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class InstallationCreateResponse(InstallationResponse):
    """Response returned upon installation creation, including one-time secret."""
    client_id: str
    client_secret: str
    enrollment_token: str


class InstallationCustomerInfo(BaseModel):
    """Customer organization summary for installation detail."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    customer_code: str
    organization_name: str
    status: str


class InstallationDetailResponse(BaseModel):
    """Comprehensive installation detail schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    installation_code: str
    name: str
    customer_id: UUID
    customer_name: Optional[str] = None
    customer_code: Optional[str] = None
    server_domain: Optional[str] = None
    server_ip: Optional[str] = None
    environment: str
    status: str
    public_key_pem: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    hardware_signature: Optional[str] = None
    last_heartbeat_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    credentials: List[InstallationCredentialResponse] = []
    events: List[InstallationEventResponse] = []
    total_events: int = 0
    total_license_links: int = 0
    total_validations: int = 0
    has_public_key: bool = False


class InstallationEnrollmentConfig(BaseModel):
    """Configuration package to configure SIMPATI 555 client for central license manager."""
    license_server_url: str
    installation_code: str
    client_id: str
    client_secret: Optional[str] = None
    environment: str
    customer_code: str
    customer_name: str
    recommended_env: str
