"""Validation checklist models for the Pentester Assistant."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class ChecklistItem(BaseModel):
    """A single checklist step with optional safety note."""

    step: int = 0
    instruction: str = ""
    safety_note: str | None = None


class ValidationChecklist(BaseModel):
    """A checklist for validating a specific vulnerability type."""

    id: str = ""
    vulnerability_type: str = ""
    title: str = ""
    items: list[ChecklistItem] = Field(default_factory=list)
    total_items: int = 0


class AssistantChecklists(BaseModel):
    """Collection of validation checklists for a project."""

    target: str = ""
    project: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    checklists: list[ValidationChecklist] = Field(default_factory=list)
    total_checklists: int = 0
