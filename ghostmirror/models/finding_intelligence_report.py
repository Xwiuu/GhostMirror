from __future__ import annotations

from datetime import datetime, timezone
from pydantic import BaseModel, Field

from ghostmirror.models.enriched_finding import EnrichedFinding


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FindingIntelligenceReport(BaseModel):
    project: str = Field(default="")
    target: str = Field(default="")
    total_findings: int = Field(default=0)
    total_enriched: int = Field(default=0)
    enriched_findings: list[EnrichedFinding] = Field(default_factory=list)
    priority_counts: dict[str, int] = Field(default_factory=lambda: {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0})
    confidence_counts: dict[str, int] = Field(default_factory=lambda: {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CONFIRMED": 0})
    severity_counts: dict[str, int] = Field(default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
    kev_count: int = Field(default=0)
    exploit_count: int = Field(default=0)
    top_findings: list[EnrichedFinding] = Field(default_factory=list)
    quick_wins: list[EnrichedFinding] = Field(default_factory=list)
    executive_summary: str = Field(default="")
    priority_matrix: dict[str, int] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
