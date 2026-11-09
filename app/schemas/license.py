"""Commercial license, module entitlement, and validation schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class LicenseCapacityInput(BaseModel):
    """Capacity specifications for a license."""
    max_members: int = Field(default=50000, ge=1)
    max_accounts: int = Field(default=200, ge=1)
    max_concurrent_users: int = Field(default=25, ge=1)
    max_storage_mb: int = Field(default=20480, ge=500)
    max_gps_points_per_month: int = Field(default=100000, ge=0)


class LicenseCreate(BaseModel):
    """Payload to issue a new commercial license."""
    customer_id: UUID
    package_id: UUID
    installation_id: Optional[UUID] = Field(None, description="Directly link to a customer installation")
    license_type: str = Field(default="COMMERCIAL")
    valid_from: datetime
    valid_until: datetime
    grace_period_days: int = Field(default=7, ge=0, le=90)
    max_installations: int = Field(default=1, ge=1)
    modules: List[str] = Field(default=["CORE", "DATA"], description="Module codes granted")
    levels: List[str] = Field(default=["DPD", "DPC"], description="Organizational levels authorized")
    capacity: LicenseCapacityInput = Field(default_factory=LicenseCapacityInput)
    notes: Optional[str] = None


class LicenseExtend(BaseModel):
    """Payload to extend/renew license validity."""
    valid_until: datetime
    reason: Optional[str] = Field(None, min_length=3, description="Reason for extension/renewal")


class LicenseStatusUpdate(BaseModel):
    """Payload to suspend, reactivate, or revoke a license."""
    status: str = Field(..., pattern="^(ACTIVE|SUSPENDED|REVOKED)$")
    reason: str = Field(..., min_length=3, description="Mandatory reason for audit trail")


class LicenseHistoryResponse(BaseModel):
    """License history audit trail item."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action: str
    remarks: Optional[str] = None
    performed_by_name: Optional[str] = None
    created_at: datetime


class LicenseDetailResponse(BaseModel):
    """Comprehensive commercial license detail."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    license_key: str
    customer_id: UUID
    customer_name: str
    customer_code: str
    package_id: UUID
    package_name: str
    license_type: str
    status: str
    computed_status: str
    issued_at: datetime
    valid_from: datetime
    valid_until: datetime
    grace_period_days: int
    max_installations: int
    modules: List[str] = []
    levels: List[str] = []
    capacity: Dict[str, Any] = {}
    installations: List[Dict[str, Any]] = []
    signature: Optional[str] = None
    signature_valid: bool = False
    snapshot_entitlements: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
    history: List[LicenseHistoryResponse] = []


class LicenseValidationRequest(BaseModel):
    """Periodic validation request from an installation."""
    license_key: str
    installation_code: str
    nonce: str
    timestamp: datetime
    installation_signature: Optional[str] = None


class LicenseValidationResponse(BaseModel):
    """Signed license validation token returned to the installation."""
    validation_status: str  # VALID, GRACE_PERIOD, RESTRICTED, REVOKED
    validation_token: str
    license_key: str
    installation_code: str
    allowed_modules: List[str]
    allowed_levels: List[str]
    capacity: Dict[str, Any]
    valid_until: datetime
    grace_period_until: Optional[datetime] = None
    next_validation_due: datetime
    signed_payload: str
    signature: str
