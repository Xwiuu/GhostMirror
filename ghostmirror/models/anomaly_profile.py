from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AnomalyProfile(BaseModel):
    target: str = ""
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    total_anomalies: int = 0
    total_signals: int = 0
    risk_level: str = "LOW"
    overall_score: int = 0
