from __future__ import annotations

from pydantic import BaseModel, Field


class AttackPathStep(BaseModel):
    order: int
    label: str
    detail: str | None = None
    finding_ref: str | None = None
    severity: str | None = None


class AttackPath(BaseModel):
    path_id: int
    title: str
    description: str
    steps: list[AttackPathStep] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: str = Field(default="INFO")
    likelihood: str = Field(default="Unknown")
    impact: str = Field(default="Unknown")
    prerequisites: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
