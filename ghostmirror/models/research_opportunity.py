from __future__ import annotations

from pydantic import BaseModel, Field


class ResearchOpportunity(BaseModel):
    title: str = ""
    opportunity_type: str = ""
    confidence: str = "LOW"
    priority: str = "LOW"
    score: int = 0
    description: str = ""
    signals: list[str] = Field(default_factory=list)
    reasoning: str = ""
    recommendation: str = ""
