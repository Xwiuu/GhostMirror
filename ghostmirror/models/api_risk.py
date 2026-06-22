from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class APIRisk(BaseModel):
    endpoint: str = ""
    method: str = "GET"
    bola_potential: bool = False
    bola_confidence: str = "LOW"
    bfla_potential: bool = False
    bfla_confidence: str = "LOW"
    mass_assignment_potential: bool = False
    mass_assignment_confidence: str = "LOW"
    auth_required: bool = False
    risk_score: int = 0
    classification: str = "LOW"
