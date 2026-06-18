"""Pydantic model representing the risk profile analysis result."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RiskProfile(BaseModel):
    """Calculated risk score and level classification for the target."""

    target: str = Field(..., description="Scan target domain or IP")
    risk_score: int = Field(..., description="Overall calculated risk score (0 to 100)")
    risk_level: str = Field(..., description="Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)")
    observations: list[str] = Field(default_factory=list, description="General risk analysis and security findings notes")
