from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    ASSET = "Asset"
    ENDPOINT = "Endpoint"
    API = "API"
    AUTH = "Auth"
    OBJECT = "Object"
    VULNERABILITY = "Vulnerability"
    HYPOTHESIS = "Hypothesis"
    BUSINESS_FUNCTION = "Business Function"


class AttackChainNode(BaseModel):
    id: str
    label: str
    node_type: NodeType
    properties: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    tags: list[str] = Field(default_factory=list)
