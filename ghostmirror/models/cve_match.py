"""Pydantic model representing a vulnerability match between a detected technology and a CVE."""

from __future__ import annotations

from pydantic import BaseModel, Field
from ghostmirror.models.cve import CVEModel


class CVEMatchModel(BaseModel):
    """Details a specific vulnerability match with confidence and risk details."""

    target: str = Field(..., description="Scan target domain or IP")
    technology: str = Field(..., description="Detected technology name")
    detected_version: str | None = Field(default=None, description="Version detected on the target")
    matched_cve: CVEModel = Field(..., description="The matched CVE details")
    match_confidence: str = Field(..., description="Confidence of the match (CONFIRMED, LIKELY, POTENTIAL, UNKNOWN)")
    match_reason: str = Field(..., description="Explanation of why the match was generated")
    risk_level: str = Field(..., description="Calculated risk level (CRITICAL, HIGH, MEDIUM, LOW)")
    priority: str = Field(..., description="Priority mapping (CRITICAL, HIGH, MEDIUM, LOW)")
    recommended_action: str = Field(..., description="Remediation steps for this match")
    recommended_scans: list[str] = Field(default_factory=list, description="Subsequent scans suggested for verification")
