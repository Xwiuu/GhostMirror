from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from ghostmirror.models.finding_confidence import ConfidenceLevel


class IndicatorType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSTI = "ssti"
    SSRF = "ssrf"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    PATH_TRAVERSAL = "path_traversal"
    AUTH_WEAKNESS = "auth_weakness"
    BUSINESS_LOGIC = "business_logic"
    INFO_LEAK = "info_leak"
    EXPOSED_SECRET = "exposed_secret"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WebIndicator(BaseModel):
    indicator_type: IndicatorType
    title: str
    description: str
    endpoint: str = ""
    parameter: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    severity: SeverityLevel = SeverityLevel.INFO
    evidence: str = ""
    technology: str = ""
    owasp_category: str = ""
    cve_reference: str = ""
    recommendation: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)
