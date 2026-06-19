from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.finding_impact import BusinessImpact, TechnicalImpact
from ghostmirror.models.finding_priority import FindingPriority


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EnrichedFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., min_length=1)
    category: str | None = Field(default=None)
    severity: str = Field(...)
    cvss: float | None = Field(default=None, ge=0, le=10)
    epss: float | None = Field(default=None, ge=0, le=1)
    kev: bool | None = Field(default=False)
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.LOW)
    likelihood: str = Field(default="Medium")
    exploitability: str = Field(default="Low")
    business_impact: str | None = Field(default=None)
    technical_impact: str | None = Field(default=None)
    priority: FindingPriority = Field(default=FindingPriority.P5)
    evidence: str | None = Field(default=None)
    recommendation: str = Field(default="")
    references: list[str] = Field(default_factory=list)
    affected_asset: str | None = Field(default=None)
    affected_component: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=_utcnow)
    source_finding: dict[str, Any] | None = Field(default=None)
