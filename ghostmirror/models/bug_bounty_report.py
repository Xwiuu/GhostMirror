from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from ghostmirror.models.bug_bounty_opportunity import BugBountyOpportunity
from ghostmirror.models.bug_bounty_profile import BugBountyProfile
from ghostmirror.models.crawled_route import CrawledRoute
from ghostmirror.models.discovered_api import DiscoveredAPI
from ghostmirror.models.discovered_secret import DiscoveredSecret
from ghostmirror.models.js_bundle_profile import JSBundleProfile
from ghostmirror.models.subdomain_profile import SubdomainProfile


class BugBountyReport(BaseModel):
    target: str = ""
    profile: BugBountyProfile = Field(default_factory=BugBountyProfile)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    headless_routes: list[CrawledRoute] = Field(default_factory=list)
    api_inventory: list[DiscoveredAPI] = Field(default_factory=list)
    js_bundles: list[JSBundleProfile] = Field(default_factory=list)
    sourcemap_findings: list[dict] = Field(default_factory=list)
    secrets: list[DiscoveredSecret] = Field(default_factory=list)
    interesting_files: list[dict] = Field(default_factory=list)
    subdomains: list[SubdomainProfile] = Field(default_factory=list)
    opportunities: list[BugBountyOpportunity] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    overall_score: int = 0
    risk_level: str = "INFO"
    total_routes: int = 0
    total_apis: int = 0
    total_bundles: int = 0
    total_secrets: int = 0
    total_opportunities: int = 0
    total_subdomains: int = 0
