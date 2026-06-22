from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class APIAttackSurface(BaseModel):
    total_endpoints: int = 0
    auth_endpoints: int = 0
    api_endpoints: int = 0
    graphql_endpoints: int = 0
    swagger_detected: bool = False
    admin_endpoints: int = 0
    sensitive_objects: int = 0
    payment_endpoints: int = 0
    object_references: int = 0
    rate_limit_classification: str = "Unknown"
    jwt_detected: bool = False
    oauth_detected: bool = False
    exposure_score: int = 0
    score_factors: dict[str, float] = Field(default_factory=dict)
