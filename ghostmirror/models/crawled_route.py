from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class CrawledRoute(BaseModel):
    url: str
    title: str = ""
    status: int = 0
    method: str = "GET"
    source: str = ""
    route_type: str = ""  # spa, link, form, xhr, fetch, websocket
    discovered_from: str = ""  # URL or page that led here
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
