from __future__ import annotations

from pydantic import BaseModel, Field


class EvidenceBlock(BaseModel):
    type: str = Field(..., description="Evidence type: http_headers, url, endpoint, parameter, cve, epss, kev, screenshot_placeholder, sanitized_secret, hypothesis_signal, attack_chain")
    label: str = Field(default="", description="Short label describing the evidence")
    content: str = Field(..., description="The evidence content (redacted if sensitive)")
    redacted: bool = Field(default=False, description="Whether sensitive data has been redacted")
