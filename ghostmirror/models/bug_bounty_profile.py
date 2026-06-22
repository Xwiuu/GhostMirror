from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class BugBountyProfile(BaseModel):
    target: str = ""
    profile_name: str = "bounty"
    max_pages: int = 10
    max_depth: int = 2
    timeout: int = 30
    rate_limit_delay: float = 1.0
    enabled_steps: list[str] = Field(default_factory=lambda: [
        "headless_crawler", "network_capture", "js_bundle_analyzer",
        "sourcemap_analyzer", "api_discovery", "parameter_mining",
        "secrets_discovery", "interesting_files", "subdomain_discovery",
    ])
    extra: dict[str, Any] = Field(default_factory=dict)
