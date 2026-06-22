from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class APIEndpoint(BaseModel):
    method: str = "GET"
    path: str
    content_type: str = ""
    auth_required: bool = False
    source: str = ""
    confidence: str = "medium"
    discovered_by: str = ""
    response_code: int = 0
    host: str = ""
    params: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
