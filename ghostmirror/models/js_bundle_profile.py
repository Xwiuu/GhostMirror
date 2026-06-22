from __future__ import annotations

from pydantic import BaseModel, Field


class JSBundleProfile(BaseModel):
    url: str = ""
    size: int = 0
    endpoints: list[str] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=list)
    comments: list[str] = Field(default_factory=list)
    feature_flags: list[str] = Field(default_factory=list)
    source_map_present: bool = False
    source_map_url: str = ""
    content_hash: str = ""
