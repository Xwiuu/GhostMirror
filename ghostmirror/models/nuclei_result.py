"""Pydantic model representing a single Nuclei scan result."""

from __future__ import annotations

from pydantic import BaseModel, Field


class NucleiResult(BaseModel):
    """Represents a standard Nuclei result item parsed from JSONL execution outputs."""

    template_id: str = Field(..., alias="template-id", description="ID of the executed template")
    template_name: str = Field(..., description="Friendly name of the template")
    severity: str = Field(..., description="Severity of the finding (critical, high, medium, low, info)")
    matched_at: str = Field(..., alias="matched-at", description="The URL/host/port matched")
    host: str = Field(..., description="Host scanned")
    ip: str | None = Field(default=None, description="IP address of host")
    curl_command: str | None = Field(default=None, alias="curl-command", description="Reproducing curl command")
    reference: list[str] = Field(default_factory=list, description="References/URLs associated with finding")
    description: str | None = Field(default=None, description="Detailed description of the vulnerability/finding")
    tags: list[str] = Field(default_factory=list, description="Tags associated with the template")
    cve: str | None = Field(default=None, description="CVE ID if applicable")
    cvss: float | None = Field(default=None, description="CVSS score if applicable")
    matcher_name: str | None = Field(default=None, alias="matcher-name", description="Specific matcher that triggered the finding")
    timestamp: str = Field(..., description="Timestamp of when the finding occurred")

    class Config:
        populate_by_name = True
