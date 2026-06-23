"""Assistant priority model — ranked investigation areas for the Pentester Assistant."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class InvestigationPriority(BaseModel):
    """A single prioritized investigation area."""

    rank: int = 0
    title: str = ""
    category: str = ""
    reason: str = ""
    severity: str = "INFO"
    confidence: str = "LOW"
    attack_chain_score: float | int | None = None
    exploitability: str | float | None = None
    kev: bool = False
    epss: float | None = None
    business_impact: str | list[str] | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class AssistantPriorities(BaseModel):
    """Ranked list of investigation priorities."""

    target: str = ""
    project: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    priorities: list[InvestigationPriority] = Field(default_factory=list)
    total_priorities: int = 0
    summary: str = ""
