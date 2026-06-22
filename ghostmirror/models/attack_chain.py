from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AttackChain(BaseModel):
    title: str = ""
    description: str = ""
    confidence: str = "LOW"
    severity: str = "LOW"
    score: int = 0
    components: list[str] = Field(default_factory=list)
    attack_vector: str = ""
    potential_impact: str = ""
    recommendation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
