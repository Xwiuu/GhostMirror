"""Pydantic model representing a Nuclei template."""

from __future__ import annotations

from pydantic import BaseModel, Field


class NucleiTemplate(BaseModel):
    """Represents a Nuclei template metadata definition."""

    id: str = Field(..., description="The unique template ID")
    name: str = Field(..., description="The name of the template")
    severity: str = Field(..., description="Template severity (critical, high, medium, low, info)")
    description: str | None = Field(default=None, description="Detailed description of what the template checks")
    tags: list[str] = Field(default_factory=list, description="Tags associated with the template")
