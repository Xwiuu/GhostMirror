"""Pydantic model for lab benchmark / profile results."""

from __future__ import annotations

from datetime import datetime, timezone


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


from pydantic import BaseModel, Field


class LabBenchmarkStep(BaseModel):
    """Duration and findings for a single scan step in a benchmark run."""

    step_name: str
    duration_seconds: float = 0.0
    findings_count: int = 0
    status: str = "completed"


class LabBenchmarkResult(BaseModel):
    """Complete benchmark result from a lab full-scan."""

    lab_id: str
    project_slug: str
    profile: str = "deep"
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    total_duration_seconds: float = 0.0
    total_findings: int = 0
    steps: list[LabBenchmarkStep] = Field(default_factory=list)
    error: str | None = None
