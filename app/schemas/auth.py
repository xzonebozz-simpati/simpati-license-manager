"""Authentication schemas for user login, credentials, and profile."""

from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    """User login request payload."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)


class LoginResponse(BaseModel):
    """User login successful response."""
    access_token: str
    token_type: str = "Bearer"
    expires_at: datetime
    user_id: UUID
    username: str
    full_name: str
    role: str


class UserResponse(BaseModel):
    """User profile data schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    is_mfa_enabled: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime
