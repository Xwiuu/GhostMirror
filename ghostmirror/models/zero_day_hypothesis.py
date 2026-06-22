from __future__ import annotations

from pydantic import BaseModel, Field


class ZeroDayHypothesis(BaseModel):
    title: str = ""
    hypothesis_type: str = ""
    confidence: str = "LOW"
    impact: str = "LOW"
    score: int = 0
    signals: list[str] = Field(default_factory=list)
    reasoning: str = ""
    attack_scenario: str = ""
    recommendation: str = ""
