from __future__ import annotations

from typing import Any

from ghostmirror.models.bug_bounty_opportunity import BugBountyOpportunity
from ghostmirror.models.bug_bounty_report import BugBountyReport
from ghostmirror.models.crawled_route import CrawledRoute
from ghostmirror.models.discovered_api import DiscoveredAPI
from ghostmirror.models.discovered_secret import DiscoveredSecret
from ghostmirror.models.js_bundle_profile import JSBundleProfile
from ghostmirror.models.subdomain_profile import SubdomainProfile


class BountyReportBuilder:
    def build(
        self,
        target: str,
        routes: list[dict[str, Any]] | list[CrawledRoute],
        apis: list[dict[str, Any]] | list[DiscoveredAPI],
        js_bundles: list[dict[str, Any]] | list[JSBundleProfile],
        sourcemap_findings: list[dict[str, Any]],
        secrets: list[dict[str, Any]] | list[DiscoveredSecret],
        interesting_files: list[dict[str, Any]],
        subdomains: list[dict[str, Any]] | list[SubdomainProfile],
        opportunities: list[dict[str, Any]],
        recommendations: list[str],
        overall_score: int,
        risk_level: str,
    ) -> BugBountyReport:
        report = BugBountyReport(
            target=target,
            overall_score=overall_score,
            risk_level=risk_level,
            total_routes=len(routes),
            total_apis=len(apis),
            total_bundles=len(js_bundles),
            total_secrets=len(secrets),
            total_opportunities=len(opportunities),
            total_subdomains=len(subdomains),
            recommendations=recommendations,
        )

        for r in routes:
            report.headless_routes.append(CrawledRoute(**r) if isinstance(r, dict) else r)

        for a in apis:
            report.api_inventory.append(DiscoveredAPI(**a) if isinstance(a, dict) else a)

        report.js_bundles = [JSBundleProfile(**b) if isinstance(b, dict) else b for b in js_bundles]
        report.sourcemap_findings = sourcemap_findings
        report.secrets = [DiscoveredSecret(**s) if isinstance(s, dict) else s for s in secrets]
        report.interesting_files = interesting_files
        report.subdomains = [SubdomainProfile(**s) if isinstance(s, dict) else s for s in subdomains]
        report.opportunities = [BugBountyOpportunity(**o) if isinstance(o, dict) else o for o in opportunities]

        return report
