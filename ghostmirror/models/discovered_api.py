from __future__ import annotations

from pydantic import BaseModel, Field


class DiscoveredAPI(BaseModel):
    method: str = "GET"
    url: str
    path: str = ""
    params: list[str] = Field(default_factory=list)
    content_type: str = ""
    auth_required_indicator: bool = False
    source: str = ""  # network_capture, js_bundle, sourcemap, endpoint_mapper, web_intel
    confidence: str = "medium"  # low, medium, high, confirmed
