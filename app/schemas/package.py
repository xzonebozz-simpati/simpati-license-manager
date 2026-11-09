"""Product catalog and license package schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class PackageModuleItem(BaseModel):
    """Module reference in a package."""
    module_code: str
    module_name: Optional[str] = None
    is_mandatory: bool = True


class PackageCreate(BaseModel):
    """Payload to create a new commercial package."""
    package_code: str = Field(..., min_length=3, max_length=50)
    package_name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = None
    default_tier: str = Field(default="STANDARD", max_length=30)
    is_active: bool = True
    # Flexible commercial configuration (non-permanent)
    price_amount: Optional[float] = Field(default=0.0, ge=0)
    billing_period: Optional[str] = Field(default="TAHUNAN")  # BULANAN, TAHUNAN, PERPETUAL, CUSTOM
    default_max_members: Optional[int] = Field(default=50000, ge=1)
    modules: List[str] = Field(default=["CORE", "DATA"], description="List of module codes included in package")
    levels: List[str] = Field(default=["DPD", "DPC"], description="Authorized organization levels (DPD, DPC, DPS, DPSS)")


class PackageUpdate(BaseModel):
    """Payload to update an existing commercial package."""
    package_name: Optional[str] = Field(None, min_length=3, max_length=100)
    description: Optional[str] = None
    default_tier: Optional[str] = None
    is_active: Optional[bool] = None
    price_amount: Optional[float] = None
    billing_period: Optional[str] = None
    default_max_members: Optional[int] = None
    modules: Optional[List[str]] = None
    levels: Optional[List[str]] = None


class PackageResponse(BaseModel):
    """Package summary response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    package_code: str
    package_name: str
    description: Optional[str] = None
    default_tier: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    modules: List[str] = []
    total_licenses: int = 0


class PackageDetailResponse(PackageResponse):
    """Detailed package response including module specifics and configuration."""
    package_modules: List[Dict[str, Any]] = []
    default_levels: List[str] = []
    price_amount: Optional[float] = 0.0
    billing_period: Optional[str] = "TAHUNAN"
    default_max_members: Optional[int] = 50000
