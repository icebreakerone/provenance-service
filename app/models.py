"""
Pydantic models for provenance record step types.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class PermissionStep(BaseModel):
    """Model for permission step in provenance records."""

    type: str = Field(default="permission", description="Step type identifier")
    scheme: str = Field(..., description="Scheme URL for the permission")
    timestamp: str = Field(..., description="ISO timestamp when permission was granted")
    account: str = Field(..., description="Account identifier")
    allows: Dict[str, List[str]] = Field(..., description="What the permission allows")
    expires: str = Field(..., description="ISO timestamp when permission expires")

    @field_validator("timestamp", "expires")
    @classmethod
    def validate_iso_timestamp(cls, v):
        """Validate that timestamp is in ISO format."""
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError("Timestamp must be in ISO format")


class OriginStep(BaseModel):
    """Model for origin step in provenance records."""

    type: str = Field(default="origin", description="Step type identifier")
    scheme: str = Field(..., description="Scheme URL for the origin")
    sourceType: str = Field(..., description="Type of data source")
    origin: str = Field(..., description="Origin URL or identifier")
    originLicence: str = Field(..., description="Licence URL for the origin")
    external: bool = Field(..., description="Whether the origin is external")
    permissions: List[str] = Field(..., description="List of permission step IDs")
    perseus_scheme: Optional[Dict[str, Any]] = Field(
        default=None, alias="perseus:scheme", description="Perseus-specific scheme data"
    )
    perseus_assurance: Optional[Dict[str, str]] = Field(
        default=None,
        alias="perseus:assurance",
        description="Perseus-specific assurance data",
    )


class TransferStep(BaseModel):
    """Model for transfer step in provenance records."""

    type: str = Field(default="transfer", description="Step type identifier")
    scheme: str = Field(..., description="Scheme URL for the transfer")
    of: str = Field(..., description="ID of the origin step being transferred")
    to: str = Field(..., description="Recipient of the transfer")
    standard: str = Field(
        ..., description="Standard URL for the data being transferred"
    )
    licence: str = Field(..., description="Licence URL for the data")
    service: str = Field(..., description="Service URL for the transfer")
    path: str = Field(..., description="API path for the service")
    parameters: Dict[str, Any] = Field(..., description="Parameters for the transfer")
    permissions: List[str] = Field(..., description="List of permission step IDs")
    transaction: str = Field(..., description="Transaction identifier")


class EdpProvenanceRecordRequest(BaseModel):
    """Model for creating a complete provenance record."""

    from_date: datetime = Field(..., description="Start date for the data period")
    to_date: datetime = Field(..., description="End date for the data period")
    permission_granted: datetime = Field(..., description="When permission was granted")
    permission_expires: datetime = Field(..., description="When permission expires")
    service_url: str = Field(..., description="Service URL for data access")
    account: str = Field(..., description="Account identifier")
    fapi_id: str = Field(..., description="FAPI transaction ID")
    cap_member: str = Field(..., description="CAP member identifier")
    origin_url: str = Field(..., description="Origin URL for the data")
    origin_license_url: str = Field(..., description="Origin license URL for the data")

    @field_validator("to_date")
    @classmethod
    def validate_date_range(cls, v, info):
        """Validate that to_date is after from_date."""
        if (
            hasattr(info, "data")
            and "from_date" in info.data
            and v <= info.data["from_date"]
        ):
            raise ValueError("to_date must be after from_date")
        return v

    @field_validator("permission_expires")
    @classmethod
    def validate_permission_expiry(cls, v, info):
        """Validate that permission expires after it was granted."""
        if (
            hasattr(info, "data")
            and "permission_granted" in info.data
            and v <= info.data["permission_granted"]
        ):
            raise ValueError("permission_expires must be after permission_granted")
        return v


class CapProvenanceRecordRequest(BaseModel):
    """Model for creating a complete provenance record."""

    edp_data_attachment: dict = Field(..., description="Encoded EDP provenance record")
    cap_member_id: str = Field(..., description="CAP member identifier")
    bank_member_id: str = Field(..., description="Bank member identifier")
    cap_account: str = Field(..., description="CAP account identifier")
    cap_permission_granted: datetime = Field(
        ..., description="When CAP permission was granted"
    )
    cap_permission_expires: datetime = Field(
        ..., description="When CAP permission expires"
    )
    grid_intensity_origin: str = Field(
        ..., description="Grid intensity data origin URL"
    )
    grid_intensity_license: str = Field(
        ..., description="Grid intensity data license URL"
    )
    postcode: str = Field(..., description="Postcode for grid intensity data")
    edp_service_url: str = Field(..., description="EDP service URL for meter readings")
    edp_member_id: str = Field(..., description="EDP member identifier")
    bank_service_url: str = Field(
        ..., description="Bank service URL for emissions reporting"
    )
    from_date: datetime = Field(..., description="Start date for the data period")
    to_date: datetime = Field(..., description="End date for the data period")

    @field_validator("to_date")
    @classmethod
    def validate_date_range(cls, v, info):
        """Validate that to_date is after from_date."""
        if (
            hasattr(info, "data")
            and "from_date" in info.data
            and v <= info.data["from_date"]
        ):
            raise ValueError("to_date must be after from_date")
        return v

    @field_validator("cap_permission_expires")
    @classmethod
    def validate_permission_expiry(cls, v, info):
        """Validate that permission expires after it was granted."""
        if (
            hasattr(info, "data")
            and "cap_permission_granted" in info.data
            and v <= info.data["cap_permission_granted"]
        ):
            raise ValueError(
                "cap_permission_expires must be after cap_permission_granted"
            )
        return v
