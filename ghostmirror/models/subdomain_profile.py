from __future__ import annotations

from pydantic import BaseModel, Field


class SubdomainProfile(BaseModel):
    hostname: str = ""
    source: str = ""  # certificate_transparency, html_link, js_bundle, dns
    resolved_ips: list[str] = Field(default_factory=list)
    http_status: int = 0
    discovered_at: str = ""
