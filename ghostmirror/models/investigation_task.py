"""Investigation task and plan models for the Pentester Assistant."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class InvestigationTask(BaseModel):
    """A single investigation task with objective, steps, and safety notes."""

    id: str = ""
    title: str = ""
    task_type: str = ""
    objective: str = ""
    evidence: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    expected_outcome: str = ""
    safety_notes: list[str] = Field(default_factory=list)
    priority: str = "P3"
    estimated_effort: str = "medium"


class InvestigationPlan(BaseModel):
    """Collection of investigation tasks for a project."""

    target: str = ""
    project: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tasks: list[InvestigationTask] = Field(default_factory=list)
    total_tasks: int = 0
