from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from ghostmirror.models.bounty_submission import BountySubmission


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class BountyReport(BaseModel):
    target: str = Field(default="", description="Target domain or application name")
    generated_at: str = Field(default_factory=_utcnow)
    submissions: list[BountySubmission] = Field(default_factory=list)
    summary_stats: dict[str, int] = Field(default_factory=lambda: {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    })
    index: dict[str, Any] = Field(default_factory=lambda: {
        "top_10": [],
        "quick_wins": [],
        "research_opportunities": [],
    })
