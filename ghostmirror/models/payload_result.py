"""PayloadResult model — safe payload execution result."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class PayloadResult(BaseModel):
    """Result of executing a single safe payload against a target endpoint."""

    target: str
    url: str
    method: str
    parameter: str
    payload_id: str
    payload_category: str
    safety_level: str
    status_code_baseline: int = 0
    status_code_probe: int = 0
    content_length_baseline: int = 0
    content_length_probe: int = 0
    content_length_diff: int = 0
    response_time_baseline: float = 0.0
    response_time_probe: float = 0.0
    matched_signal: str | None = None
    signal_detail: str | None = None
    body_snippet_sanitized: str | None = None
    evidence_path: str | None = None
    blocked: bool = False
    blocked_reason: str | None = None
    dry_run: bool = False
    error: str | None = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
