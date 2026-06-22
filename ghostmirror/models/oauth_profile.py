from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class OAuthProfile(BaseModel):
    detected: bool = False
    providers: list[str] = Field(default_factory=list)
    endpoints: dict[str, list[str]] = Field(default_factory=dict)
    has_authorize: bool = False
    has_token: bool = False
    has_userinfo: bool = False
    has_jwks: bool = False
