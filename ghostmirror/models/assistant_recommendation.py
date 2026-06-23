"""Assistant recommendation model for the Pentester Assistant."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class AssistantRecommendation(BaseModel):
    """A single recommendation with evidence-backed reasoning."""

    id: str = ""
    title: str = ""
    category: str = ""
    reasoning: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: str = "LOW"
    risk_narrative: str = ""
    manual_validation_required: bool = True


class AssistantRecommendations(BaseModel):
    """Collection of recommendations for a project."""

    target: str = ""
    project: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    recommendations: list[AssistantRecommendation] = Field(default_factory=list)
    total: int = 0
