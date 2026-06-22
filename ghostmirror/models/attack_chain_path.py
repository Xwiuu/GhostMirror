from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AttackChainPath(BaseModel):
    id: str
    title: str
    chain_type: str = ""
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    signals: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = 0.0
    likelihood: float = 0.0
    impact: float = 0.0
    exploitability: float = 0.0
    business_impact: list[str] = Field(default_factory=list)
    technical_impact: list[str] = Field(default_factory=list)
    priority: str = "medium"
    score: float = 0.0
    evidence_summary: str = ""
    manual_validation_steps: list[str] = Field(default_factory=list)
    defensive_recommendations: list[str] = Field(default_factory=list)
