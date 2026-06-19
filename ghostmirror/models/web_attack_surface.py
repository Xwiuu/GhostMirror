from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class IndicatorSummary(BaseModel):
    sql_injection: int = 0
    xss: int = 0
    ssti: int = 0
    ssrf: int = 0
    idor: int = 0
    open_redirect: int = 0
    path_traversal: int = 0
    auth_weakness: int = 0
    business_logic: int = 0
    info_leak: int = 0
    exposed_secret: int = 0


class WebAttackSurface(BaseModel):
    total_endpoints: int = 0
    auth_endpoints: int = 0
    api_endpoints: int = 0
    admin_endpoints: int = 0
    js_endpoints: int = 0
    param_count: int = 0
    sensitive_params: int = 0
    forms_count: int = 0
    indicator_summary: IndicatorSummary = Field(default_factory=IndicatorSummary)
    high_confidence_indicators: int = 0
    overall_exposure: str = "LOW"
    extra: dict[str, Any] = Field(default_factory=dict)
