"""Pydantic model representing the target's attack surface profile."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttackSurfaceProfile(BaseModel):
    """Aggregates all components of the target footprint to identify attack vectors."""

    target: str = Field(..., description="Scan target domain or IP")
    web_servers: list[str] = Field(default_factory=list, description="Identified web server technologies")
    frameworks: list[str] = Field(default_factory=list, description="Identified backend or frontend frameworks")
    cms: list[str] = Field(default_factory=list, description="Identified Content Management Systems")
    databases: list[str] = Field(default_factory=list, description="Identified database services")
    external_services: list[str] = Field(default_factory=list, description="Identified external services (CDN, payments, etc.)")
    technologies: list[str] = Field(default_factory=list, description="All detected technologies")
    potential_entry_points: list[str] = Field(default_factory=list, description="Endpoints or components with direct exposure")
    high_value_assets: list[str] = Field(default_factory=list, description="High-value target assets (payment processing, databases)")
    risk_score: int = Field(default=0, description="Overall risk score associated with this attack surface")
