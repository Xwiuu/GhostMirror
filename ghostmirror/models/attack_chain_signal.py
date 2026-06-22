from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SignalType(str, Enum):
    EXPOSED_ADMIN = "exposed_admin"
    EXPOSED_API = "exposed_api"
    SENSITIVE_OBJECT = "sensitive_object"
    JWT_DETECTED = "jwt_detected"
    OAUTH_DETECTED = "oauth_detected"
    BOLA_INDICATOR = "bola_indicator"
    BFLA_INDICATOR = "bfla_indicator"
    MASS_ASSIGNMENT_INDICATOR = "mass_assignment_indicator"
    CVE_KNOWN_EXPLOITED = "cve_known_exploited"
    PUBLIC_EXPLOIT_AVAILABLE = "public_exploit_available"
    MISSING_HEADER = "missing_header"
    SOURCE_MAP_EXPOSED = "source_map_exposed"
    SECRET_EXPOSED = "secret_exposed"
    BUSINESS_LOGIC_SURFACE = "business_logic_surface"
    ZERO_DAY_HYPOTHESIS = "zero_day_hypothesis"
    GRAPHQL_SURFACE = "graphql_surface"
    RATE_LIMIT_UNKNOWN = "rate_limit_unknown"
    AUTH_SURFACE = "auth_surface"


class AttackChainSignal(BaseModel):
    id: str
    source_module: str = ""
    signal_type: SignalType
    asset: str = ""
    endpoint: str = ""
    parameter: str = ""
    technology: str = ""
    severity: str = "info"
    confidence: float = 0.5
    evidence: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
