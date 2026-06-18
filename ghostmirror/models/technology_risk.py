"""Pydantic model representing technology risk and exposure intelligence."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TechnologyRisk(BaseModel):
    """Represents risk and scanner recommendations mapped from the threat intelligence knowledge base."""

    technology: str = Field(..., description="Name of the technology (e.g. Apache, WordPress)")
    category: str = Field(..., description="Category of the technology (e.g. WEB SERVER, CMS)")
    risk_level: str = Field(..., description="Calculated risk level (LOW, MEDIUM, HIGH, CRITICAL)")
    attack_surface: list[str] = Field(default_factory=list, description="Associated attack surface areas")
    recommended_scans: list[str] = Field(default_factory=list, description="Scans recommended for this technology")
    common_exposures: list[str] = Field(default_factory=list, description="Common security exposures")
    confidence: float = Field(default=1.0, description="Overall detection confidence score (0.0 to 1.0)")
