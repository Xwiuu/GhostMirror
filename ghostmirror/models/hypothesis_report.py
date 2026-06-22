from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HypothesisReport(BaseModel):
    target: str = ""
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    attack_chains: list[dict[str, Any]] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    opportunities: list[dict[str, Any]] = Field(default_factory=list)
    research_queue: list[dict[str, Any]] = Field(default_factory=list)
    overall_score: int = 0
    risk_level: str = "LOW"
    total_signals: int = 0
    total_hypotheses: int = 0
    total_opportunities: int = 0
    total_attack_chains: int = 0
