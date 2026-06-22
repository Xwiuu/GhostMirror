from __future__ import annotations

from pydantic import BaseModel, Field


class BugBountyOpportunity(BaseModel):
    title: str
    type: str = ""  # sensitive_param, auth_endpoint, api_endpoint, exposed_sourcemap, potential_secret, interesting_file, business_logic, payment, admin
    score: int = 0
    severity: str = "LOW"
    description: str = ""
    endpoints_affected: list[str] = Field(default_factory=list)
    recommendation: str = ""
