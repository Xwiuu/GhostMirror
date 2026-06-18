"""Pydantic models for fingerprint profile and AI detection results."""

from __future__ import annotations

from pydantic import BaseModel, Field
from ghostmirror.models.technology import TechnologyModel


class AIProfile(BaseModel):
    """Results from the AI construction detection engine."""

    ai_probability: float = Field(..., description="AI generation probability (0 to 100)")
    signals_detected: list[str] = Field(default_factory=list, description="Specific indicators found")
    frameworks_detected: list[str] = Field(default_factory=list, description="AI frameworks or wrapper tools found")
    llm_integrations: list[str] = Field(default_factory=list, description="LLM providers referenced")
    observations: str = Field(default="", description="Analysis notes")


class FingerprintProfile(BaseModel):
    """Unified technology profile of the target."""

    target: str = Field(..., description="Scan target domain or IP")
    webserver: str | None = Field(default=None, description="Web server name")
    backend_language: str | None = Field(default=None, description="Backend development language")
    backend_framework: str | None = Field(default=None, description="Backend application framework")
    frontend_framework: str | None = Field(default=None, description="Frontend framework or library")
    cms: str | None = Field(default=None, description="Content Management System")
    builder: str | None = Field(default=None, description="No-code/Low-code page builder")
    hosting: str | None = Field(default=None, description="Hosting provider or cloud infrastructure")
    waf: str | None = Field(default=None, description="Web Application Firewall")
    cdn: str | None = Field(default=None, description="Content Delivery Network")
    analytics: list[str] = Field(default_factory=list, description="Web analytics and tracking tools")
    payment_providers: list[str] = Field(default_factory=list, description="Payment processor scripts/APIs")
    technologies: list[TechnologyModel] = Field(default_factory=list, description="All detected technologies")
    confidence_score: float = Field(default=100.0, description="Overall scan confidence score (0 to 100)")
