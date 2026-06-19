from __future__ import annotations

from pydantic import BaseModel, Field


class WAFProfile(BaseModel):
    detected: bool = False
    vendor: str | None = None
    confidence: int = 0


class CDNProfile(BaseModel):
    detected: bool = False
    vendor: str | None = None
    confidence: int = 0


class HostingProfile(BaseModel):
    detected: bool = False
    provider: str | None = None
    confidence: int = 0


class DNSFinding(BaseModel):
    record_type: str
    status: str
    details: str | None = None


class DNSProfile(BaseModel):
    records: dict[str, list[str]] = Field(default_factory=dict)
    findings: list[DNSFinding] = Field(default_factory=list)
    spf_missing: bool = False
    dmarc_missing: bool = False
    dkim_missing: bool = False


class AttackSurfaceProfile(BaseModel):
    target: str = Field(..., description="Scan target domain or IP")
    web_servers: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    cms: list[str] = Field(default_factory=list)
    databases: list[str] = Field(default_factory=list)
    external_services: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    services_exposed: list[str] = Field(default_factory=list)
    waf: WAFProfile = Field(default_factory=WAFProfile)
    cdn: CDNProfile = Field(default_factory=CDNProfile)
    hosting: HostingProfile = Field(default_factory=HostingProfile)
    dns: DNSProfile = Field(default_factory=DNSProfile)
    potential_entry_points: list[str] = Field(default_factory=list)
    high_value_assets: list[str] = Field(default_factory=list)
    attack_surface_score: int = Field(default=0, ge=0, le=100)
    classification: str = Field(default="Unknown")
    observations: list[str] = Field(default_factory=list)
