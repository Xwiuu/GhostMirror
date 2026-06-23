"""Assistant report model — full output of the Pentester Assistant Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

SAFETY_DISCLAIMER = (
    "The Pentester Assistant provides guidance for authorized manual review only. "
    "It does not confirm exploitation or replace professional judgment."
)


class AssistantReport(BaseModel):
    """Complete assistant report combining priorities, next steps, checklists, and narrative."""

    target: str = ""
    project: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    priorities: list[dict[str, Any]] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    investigation_plan: list[dict[str, Any]] = Field(default_factory=list)
    validation_checklists: list[dict[str, Any]] = Field(default_factory=list)
    questions: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    risk_narrative: str = ""
    executive_summary: str = ""
    safety_disclaimer: str = SAFETY_DISCLAIMER
    hackerone_guidance: list[dict[str, Any]] = Field(default_factory=list)
    zero_day_notes: list[dict[str, Any]] = Field(default_factory=list)
    total_priorities: int = 0
    total_tasks: int = 0
    total_checklists: int = 0
    total_questions: int = 0
