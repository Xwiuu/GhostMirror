from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class AnomalySignal(BaseModel):
    signal_type: str = ""
    source: str = ""
    endpoint: str = ""
    method: str = "GET"
    expected: str | int | None = None
    observed: str | int | None = None
    severity: str = "LOW"
    description: str = ""
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
