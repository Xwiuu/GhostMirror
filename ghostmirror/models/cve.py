"""Pydantic model representing a single CVE vulnerability."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CVEModel(BaseModel):
    """Represents standard metadata and criteria for a CVE vulnerability."""

    cve_id: str = Field(..., description="CVE ID (e.g. CVE-2021-41773)")
    title: str = Field(..., description="Short title describing the vulnerability")
    description: str = Field(..., description="Detailed description of the vulnerability")
    severity: str = Field(..., description="Vulnerability severity level (CRITICAL, HIGH, MEDIUM, LOW)")
    cvss_score: float = Field(..., description="CVSS score (0.0 to 10.0)")
    cvss_vector: str | None = Field(default=None, description="CVSS vector string")
    affected_product: str = Field(..., description="Name of the affected product (e.g. Apache)")
    affected_versions: list[str] = Field(default_factory=list, description="List of version rules that are affected")
    fixed_versions: list[str] = Field(default_factory=list, description="List of version rules that are fixed")
    references: list[str] = Field(default_factory=list, description="List of reference URLs")
    published_at: str | None = Field(default=None, description="Publication timestamp")
    updated_at: str | None = Field(default=None, description="Last update timestamp")
    exploit_available: bool = Field(default=False, description="Whether a public exploit is available")
    kev_listed: bool = Field(default=False, description="Whether the CVE is listed in CISA KEV catalog")
    source: str = Field(default="local", description="Source of the CVE data")
