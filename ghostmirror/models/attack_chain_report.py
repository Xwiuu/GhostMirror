from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class AttackChainReport(BaseModel):
    target: str = ""
    project: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_signals: int = 0
    total_nodes: int = 0
    total_edges: int = 0
    total_chains: int = 0
    signals: list[dict[str, Any]] = Field(default_factory=list)
    graph: dict[str, Any] = Field(default_factory=dict)
    chains: list[dict[str, Any]] = Field(default_factory=list)
    priorities: list[dict[str, Any]] = Field(default_factory=list)
    top_chains: list[dict[str, Any]] = Field(default_factory=list)
    priority_matrix: list[dict[str, Any]] = Field(default_factory=list)
    business_impact_summary: list[dict[str, Any]] = Field(default_factory=list)
    technical_impact_summary: list[str] = Field(default_factory=list)
    attack_graph_summary: dict[str, Any] = Field(default_factory=dict)
    overall_score: float = 0.0
    risk_level: str = "info"
