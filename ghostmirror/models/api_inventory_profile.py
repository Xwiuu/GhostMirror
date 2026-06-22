from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class APIInventoryProfile(BaseModel):
    total_endpoints: int = 0
    total_methods: dict[str, int] = Field(default_factory=dict)
    total_sources: dict[str, int] = Field(default_factory=dict)
    total_confidence: dict[str, int] = Field(default_factory=dict)
    auth_required_count: int = 0
    content_types: dict[str, int] = Field(default_factory=dict)
    endpoints: list[dict[str, Any]] = Field(default_factory=list)
