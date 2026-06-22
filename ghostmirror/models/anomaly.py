from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Anomaly(BaseModel):
    title: str = ""
    description: str = ""
    endpoint: str = ""
    signals: list[dict[str, Any]] = Field(default_factory=list)
    severity: str = "LOW"
    confidence: str = "LOW"
    score: int = 0
    category: str = ""
