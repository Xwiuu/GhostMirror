from __future__ import annotations

from pydantic import BaseModel, Field


class ReproductionStep(BaseModel):
    step_number: int = Field(default=1, ge=1, description="Step sequence number")
    description: str = Field(..., min_length=1, description="Safe, observacional step to reproduce the finding")
    expected_observation: str = Field(default="", description="What the reviewer should observe after performing the step")
    safe: bool = Field(default=True, description="Whether this step is safe (non-destructive, no active exploitation)")
