"""OWASP Top 10 finding domain model — category enum and structured finding."""

from __future__ import annotations

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from ghostmirror.modules.models.finding import FindingSeverity


class OWASPCategory(str, Enum):
    A01 = "Broken Access Control Indicators"
    A02 = "Cryptographic Failures"
    A03 = "Injection Indicators"
    A04 = "Insecure Design Indicators"
    A05 = "Security Misconfiguration"
    A06 = "Vulnerable Components"
    A07 = "Identification and Authentication Indicators"
    A08 = "Software and Data Integrity Indicators"
    A09 = "Security Logging Indicators"
    A10 = "SSRF Indicators"


class OWASPFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    category: OWASPCategory
    title: str
    description: str
    severity: FindingSeverity
    target: str
    evidence: str = ""
    recommendation: str = ""
    owasp_score: int = 0
