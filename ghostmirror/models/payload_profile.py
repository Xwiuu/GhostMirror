"""PayloadProfile model — aggregate result of a safe payload scan session."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class SafetyLevel(str, Enum):
    PASSIVE = "PASSIVE"
    SAFE_REFLECTION = "SAFE_REFLECTION"
    SAFE_ERROR_TRIGGER = "SAFE_ERROR_TRIGGER"
    MANUAL_CONFIRMATION_REQUIRED = "MANUAL_CONFIRMATION_REQUIRED"
    BLOCKED = "BLOCKED"


class PayloadCategory(str, Enum):
    XSS_REFLECTION = "XSS_REFLECTION"
    SQL_ERROR_INDICATOR = "SQL_ERROR_INDICATOR"
    OPEN_REDIRECT_INDICATOR = "OPEN_REDIRECT_INDICATOR"
    SSRF_SURFACE_INDICATOR = "SSRF_SURFACE_INDICATOR"
    PATH_TRAVERSAL_INDICATOR = "PATH_TRAVERSAL_INDICATOR"
    HEADER_INJECTION_INDICATOR = "HEADER_INJECTION_INDICATOR"
    TEMPLATE_INJECTION_INDICATOR = "TEMPLATE_INJECTION_INDICATOR"


class PayloadProfile(BaseModel):
    """Aggregate profile for a payload scan session."""

    target: str
    total_payloads_registered: int = 0
    payloads_executed: int = 0
    payloads_blocked: int = 0
    findings_generated: int = 0
    categories_tested: list[str] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "INFO"
    dry_run: bool = False
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
