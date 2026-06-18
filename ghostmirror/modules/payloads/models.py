"""PayloadDefinition model — a single registered safe payload."""

from __future__ import annotations

from pydantic import BaseModel, Field

from ghostmirror.models.payload_profile import PayloadCategory, SafetyLevel


class PayloadDefinition(BaseModel):
    """Metadata definition for a single safe, non-destructive payload."""

    id: str
    name: str
    category: PayloadCategory
    description: str
    value: str
    method: str = Field(default="GET")
    parameter_type: str = Field(default="query")
    safety_level: SafetyLevel = Field(default=SafetyLevel.SAFE_REFLECTION)
    requires_confirmation: bool = False
    destructive: bool = False
    expected_signal: str | None = None
