from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from ghostmirror.models.bounty_severity import BountyPriority, BountySeverity
from ghostmirror.models.evidence_block import EvidenceBlock
from ghostmirror.models.reproduction_step import ReproductionStep


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class BountySubmission(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., min_length=1, description="Clear, concise title of the vulnerability")
    severity: BountySeverity = Field(default=BountySeverity.INFORMATIONAL, description="Severity in bounty format (Informational, Low, Medium, High, Critical)")
    priority: BountyPriority = Field(default=BountyPriority.P5, description="Priority in P1-P5 format")
    affected_asset: str = Field(default="", description="The affected URL, domain, or endpoint")
    affected_endpoint: str = Field(default="", description="Specific path or endpoint affected")
    category: str = Field(default="", description="Vulnerability category (e.g. Missing Security Header, Open Redirect Indicator)")
    cwe: str = Field(default="", description="CWE identifier (e.g. CWE-693)")
    owasp: str = Field(default="", description="OWASP Top 10 category (e.g. A05:2021)")
    cvss: float | None = Field(default=None, ge=0, le=10, description="CVSS score")
    epss: float | None = Field(default=None, ge=0, le=1, description="EPSS probability score")
    confidence: str = Field(default="Medium", description="Confidence level: Low, Medium, High, Confirmed")
    summary: str = Field(default="", description="Short executive summary of the finding")
    impact: dict[str, str] = Field(default_factory=lambda: {"business": "", "technical": ""}, description="Business and technical impact descriptions")
    technical_details: str = Field(default="", description="Technical description of the vulnerability")
    steps_to_reproduce: list[ReproductionStep] = Field(default_factory=list, description="Safe, non-destructive reproduction steps")
    evidence: list[EvidenceBlock] = Field(default_factory=list, description="Evidence blocks (headers, URLs, sanitized data)")
    remediation: str = Field(default="", description="Specific remediation recommendation")
    references: list[str] = Field(default_factory=list, description="Reference URLs (OWASP, CWE, PortSwigger, etc.)")
    generated_from: str = Field(default="", description="Source type: enriched_finding, vulnerability_intelligence, web_indicator, api_indicator, bug_bounty_opportunity, zero_day_hypothesis")
    created_at: str = Field(default_factory=_utcnow, description="Timestamp when submission was generated")
