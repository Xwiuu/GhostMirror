"""Assistant context model — aggregated intelligence data for the Pentester Assistant."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class AssistantContext(BaseModel):
    """Consolidated intelligence context consumed by the Pentester Assistant Engine."""

    target: str = ""
    project: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    top_findings: list[dict[str, Any]] = Field(default_factory=list)
    top_cves: list[dict[str, Any]] = Field(default_factory=list)
    top_attack_chains: list[dict[str, Any]] = Field(default_factory=list)
    top_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    top_api_risks: list[dict[str, Any]] = Field(default_factory=list)
    top_bounty_opportunities: list[dict[str, Any]] = Field(default_factory=list)
    quick_wins: list[dict[str, Any]] = Field(default_factory=list)
    business_risks: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    total_sources_loaded: int = 0
