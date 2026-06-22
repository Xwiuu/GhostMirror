from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class EdgeType(str, Enum):
    EXPOSES = "exposes"
    DEPENDS_ON = "depends_on"
    AUTHENTICATES_WITH = "authenticates_with"
    AFFECTS = "affects"
    INCREASES_RISK_OF = "increases_risk_of"
    RELATED_TO = "related_to"


class AttackChainEdge(BaseModel):
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""
    weight: float = 1.0
    metadata: dict = Field(default_factory=dict)
