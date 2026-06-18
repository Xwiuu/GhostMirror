"""OWASP profile model — summary of an OWASP Top 10 Light assessment."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel

from ghostmirror.models.owasp_finding import OWASPFinding


class OWASPProfile(BaseModel):
    target: str
    categories: list[str]
    findings: list[OWASPFinding]
    risk_score: int
    risk_level: str
    recommendations: list[str]
    scan_timestamp: str = ""
