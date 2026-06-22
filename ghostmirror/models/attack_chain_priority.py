from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AttackChainPriority(BaseModel):
    chain_id: str
    title: str
    score: float = 0.0
    confidence: float = 0.0
    likelihood: float = 0.0
    impact: float = 0.0
    exploitability: float = 0.0
    business_impact: list[str] = Field(default_factory=list)
    priority: str = "medium"
    rank: int = 0
