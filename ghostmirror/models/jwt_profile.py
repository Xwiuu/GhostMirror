from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class JWTProfile(BaseModel):
    detected: bool = False
    redacted_tokens: list[str] = Field(default_factory=list)
    algorithms: list[str] = Field(default_factory=list)
    has_kid: bool = False
    has_typ: bool = False
    has_exp: bool = False
    has_none_alg_indicator: bool = False
    weak_algorithms: list[str] = Field(default_factory=list)
    issuers: list[str] = Field(default_factory=list)
    audiences: list[str] = Field(default_factory=list)
    total_tokens_found: int = 0
