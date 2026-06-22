from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class APISecurityReport(BaseModel):
    target: str = ""
    api_inventory: dict[str, Any] = Field(default_factory=dict)
    swagger_profile: dict[str, Any] | None = None
    graphql_profile: dict[str, Any] | None = None
    jwt_profile: dict[str, Any] | None = None
    oauth_profile: dict[str, Any] | None = None
    object_inventory: list[dict[str, Any]] = Field(default_factory=list)
    rate_limit_profile: dict[str, Any] | None = None
    attack_surface: dict[str, Any] | None = None
    bola_indicators: list[dict[str, Any]] = Field(default_factory=list)
    bfla_indicators: list[dict[str, Any]] = Field(default_factory=list)
    mass_assignment_indicators: list[dict[str, Any]] = Field(default_factory=list)
    correlations: list[dict[str, Any]] = Field(default_factory=list)
    opportunities: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    overall_score: int = 0
    risk_level: str = "LOW"
