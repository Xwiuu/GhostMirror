from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from ghostmirror.models.web_endpoint import WebEndpoint
from ghostmirror.models.web_indicator import SeverityLevel, WebIndicator
from ghostmirror.models.parameter_profile import ParameterProfile
from ghostmirror.models.web_attack_surface import WebAttackSurface


class CorrelationResult(BaseModel):
    title: str
    correlation_type: str
    score: int = 0
    classification: str = "LOW"
    endpoint: str = ""
    parameter: str = ""
    technology: str = ""
    owasp_category: str = ""
    cve_reference: str = ""
    description: str = ""
    indicator_refs: list[str] = Field(default_factory=list)
    recommendation: str = ""


class OpportunityScore(BaseModel):
    title: str
    score: int
    classification: str
    correlation_ref: str = ""
    endpoint: str = ""
    indicator_type: str = ""
    summary: str = ""


class BusinessLogicArea(BaseModel):
    area: str
    endpoints: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    risk: str = "info"
    description: str = ""


class WebIntelligenceReport(BaseModel):
    target: str = ""
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    endpoints: list[WebEndpoint] = Field(default_factory=list)
    parameters: list[ParameterProfile] = Field(default_factory=list)
    indicators: list[WebIndicator] = Field(default_factory=list)
    correlations: list[CorrelationResult] = Field(default_factory=list)
    opportunities: list[OpportunityScore] = Field(default_factory=list)
    business_areas: list[BusinessLogicArea] = Field(default_factory=list)
    auth_profile: dict[str, Any] = Field(default_factory=dict)
    js_findings: dict[str, Any] = Field(default_factory=dict)
    attack_surface: WebAttackSurface | None = None
    overall_score: int = 0
    risk_level: str = "INFO"
    total_endpoints: int = 0
    total_parameters: int = 0
    total_indicators: int = 0
    total_opportunities: int = 0
