from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.core.logger import get_logger
from ghostmirror.models.bug_bounty_report import BugBountyReport
from ghostmirror.modules.bug_bounty.api_discovery import APIDiscovery
from ghostmirror.modules.bug_bounty.headless_crawler import HeadlessCrawler
from ghostmirror.modules.bug_bounty.interesting_files import InterestingFiles
from ghostmirror.modules.bug_bounty.js_bundle_analyzer import JSBundleAnalyzer
from ghostmirror.modules.bug_bounty.network_capture import NetworkCapture
from ghostmirror.modules.bug_bounty.parameter_mining import ParameterMining
from ghostmirror.modules.bug_bounty.recommendations import BountyRecommendations
from ghostmirror.modules.bug_bounty.recon_profiles import ReconProfiles
from ghostmirror.modules.bug_bounty.report_builder import BountyReportBuilder
from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard
from ghostmirror.modules.bug_bounty.scoring import BountyScoring
from ghostmirror.modules.bug_bounty.secrets_discovery import SecretsDiscovery
from ghostmirror.modules.bug_bounty.sourcemap_analyzer import SourcemapAnalyzer
from ghostmirror.modules.bug_bounty.subdomain_discovery import SubdomainDiscovery

logger = get_logger()


class BugBountyEngine:
    def __init__(self, profile: str = "bounty") -> None:
        self.profile = profile
        self.headless_crawler = HeadlessCrawler()
        self.network_capture = NetworkCapture()
        self.js_bundle_analyzer = JSBundleAnalyzer()
        self.sourcemap_analyzer = SourcemapAnalyzer()
        self.api_discovery = APIDiscovery()
        self.parameter_mining = ParameterMining()
        self.secrets_discovery = SecretsDiscovery()
        self.interesting_files = InterestingFiles()
        self.subdomain_discovery = SubdomainDiscovery()
        self.scope_guard: BountyScopeGuard | None = None
        self.scoring = BountyScoring()
        self.recommendations = BountyRecommendations()
        self.report_builder = BountyReportBuilder()

    def analyze_project(
        self,
        project_path: Path | str,
        target_url: str | None = None,
    ) -> dict[str, Any]:
        project_path = Path(project_path)
        logger.info("BUG_BOUNTY_ENGINE_START project={} profile={}", project_path.name, self.profile)

        profiles_dir = project_path / "profiles" / "bug_bounty"
        evidence_dir = project_path / "evidence" / "bug_bounty"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        tech_profile = self._load_json(project_path / "profiles" / "technology_profile.json") or {}
        target = target_url or tech_profile.get("target", "")

        if not target:
            logger.warning("BUG_BOUNTY_SKIPPED no target available")
            return {"status": "skipped", "reason": "No target available"}

        normalized_target = target if target.startswith("http") else f"https://{target}"

        self.scope_guard = BountyScopeGuard(
            project_path=project_path,
            max_pages=10,
            max_depth=2,
            timeout=30,
        )
        self.scope_guard.load_scope()

        steps = ReconProfiles.get_steps(self.profile)

        routes: list[dict[str, Any]] = []
        captured_requests: list[dict[str, Any]] = []
        captured_forms: list[dict[str, Any]] = []
        js_bundle_profiles: list[dict[str, Any]] = []
        sourcemap_results: list[dict[str, Any]] = []
        api_inventory: list[dict[str, Any]] = []
        mined_params: list[dict[str, Any]] = []
        discovered_secrets: list[dict[str, Any]] = []
        interesting_files_results: list[dict[str, Any]] = []
        subdomain_results: list[dict[str, Any]] = []

        for step in steps:
            try:
                if step == "headless_crawler":
                    crawled = self.headless_crawler.crawl(normalized_target, self.scope_guard)
                    routes = self.headless_crawler.get_routes()
                    captured_requests = self.headless_crawler.get_captured_requests()
                    captured_forms = self.headless_crawler.get_captured_forms()
                    self._save_json(evidence_dir / "headless_routes.json", routes)
                    self._save_json(profiles_dir / "headless_routes.json", routes)

                elif step == "network_capture":
                    self.network_capture.ingest(captured_requests, self.scope_guard)
                    captured = self.network_capture.get_captured()
                    if captured:
                        self._save_json(evidence_dir / "network_capture.json", captured)

                elif step == "js_bundle_analyzer":
                    js_urls = self._collect_js_urls(normalized_target,
                                                     project_path / "profiles" / "web_intelligence")
                    profiles = self.js_bundle_analyzer.analyze(js_urls)
                    js_bundle_profiles = [p.model_dump(mode="json") for p in profiles]
                    self._save_json(profiles_dir / "js_bundle_profile.json", js_bundle_profiles)

                    for p in profiles:
                        if p.source_map_url:
                            sourcemap_results.append({
                                "js_url": p.url,
                                "sourcemap_url": p.source_map_url,
                                "found": True,
                                "exposed": False,
                                "files": [],
                                "endpoints": [],
                                "comments": [],
                            })

                elif step == "sourcemap_analyzer":
                    js_urls_sm = self._collect_js_urls(normalized_target,
                                                        project_path / "profiles" / "web_intelligence")
                    sourcemap_results = self.sourcemap_analyzer.analyze(js_urls_sm, target)
                    self._save_json(profiles_dir / "sourcemap_profile.json", sourcemap_results)

                elif step == "api_discovery":
                    js_endpoints = self.js_bundle_analyzer.get_all_endpoints(
                        [p for p in js_bundle_profiles]
                    )
                    network_entries = self.network_capture.get_api_candidates()
                    sourcemap_eps = []
                    for sm in sourcemap_results:
                        sourcemap_eps.extend(sm.get("endpoints", []))

                    web_intel_endpoints = self._load_json_list(
                        project_path / "profiles" / "web_intelligence" / "endpoint_inventory.json"
                    )

                    apis = self.api_discovery.combine(
                        network_capture_entries=network_entries if network_entries else None,
                        js_endpoints=js_endpoints if js_endpoints else None,
                        sourcemap_endpoints=sourcemap_eps if sourcemap_eps else None,
                        web_intel_endpoints=web_intel_endpoints if web_intel_endpoints else None,
                    )
                    api_inventory = [a.model_dump(mode="json") for a in apis]
                    self._save_json(profiles_dir / "api_inventory.json", api_inventory)

                elif step == "parameter_mining":
                    sources = []
                    for r in routes:
                        sources.append({"url": r.get("url", ""), "source": "headless", "form_params": [], "js_params": []})
                    for f in captured_forms:
                        inputs = f.get("inputs", [])
                        form_params = [i.get("name", "") for i in inputs if i.get("name")]
                        sources.append({
                            "url": f.get("action", ""),
                            "source": "headless_form",
                            "form_params": form_params,
                            "js_params": [],
                        })
                    mined_params = self.parameter_mining.mine(sources)
                    self._save_json(profiles_dir / "parameter_mining.json", mined_params)

                elif step == "secrets_discovery":
                    html_content = ""
                    js_content = ""
                    for p in js_bundle_profiles:
                        js_content += "\n".join(p.get("secrets", [])) + "\n"

                    for r in routes[:5]:
                        try:
                            import httpx
                            resp = httpx.get(r.get("url", ""), timeout=10.0, verify=False)
                            html_content += resp.text + "\n"
                        except Exception:
                            pass

                    secrets = self.secrets_discovery.scan(html_content, js_content, normalized_target, target)
                    discovered_secrets = [s.model_dump(mode="json") for s in secrets]
                    self._save_json(profiles_dir / "secrets_discovery.json", discovered_secrets)

                elif step == "interesting_files":
                    interesting_files_results = self.interesting_files.check(normalized_target, self.scope_guard)
                    self._save_json(profiles_dir / "interesting_files.json", interesting_files_results)

                elif step == "subdomain_discovery":
                    html_agg = ""
                    for r in routes[:10]:
                        try:
                            import httpx
                            resp = httpx.get(r.get("url", ""), timeout=10.0, verify=False)
                            html_agg += resp.text + "\n"
                        except Exception:
                            pass
                    from urllib.parse import urlparse
                    parsed_domain = urlparse(normalized_target).hostname or normalized_target
                    subs = self.subdomain_discovery.discover(parsed_domain, html_agg)
                    subdomain_results = [s.model_dump(mode="json") for s in subs]
                    self._save_json(profiles_dir / "subdomain_profile.json", subdomain_results)

            except ToolNotFoundError:
                logger.warning("BUG_BOUNTY_STEP_SKIPPED step={}", step)
            except Exception as exc:
                logger.warning("BUG_BOUNTY_STEP_ERROR step={} error={}", step, exc)

        opportunities, overall_score, risk_level = self.scoring.calculate(
            routes=routes,
            apis=api_inventory,
            js_bundles=js_bundle_profiles,
            sourcemap_findings=sourcemap_results,
            secrets=discovered_secrets,
            interesting_files=interesting_files_results,
            parameters=mined_params,
        )

        opp_dicts = [o.model_dump(mode="json") for o in opportunities]
        self._save_json(profiles_dir / "bug_bounty_opportunities.json", opp_dicts)

        report = self.report_builder.build(
            target=normalized_target,
            routes=routes,
            apis=api_inventory,
            js_bundles=js_bundle_profiles,
            sourcemap_findings=sourcemap_results,
            secrets=discovered_secrets,
            interesting_files=interesting_files_results,
            subdomains=subdomain_results,
            opportunities=opp_dicts,
            recommendations=[],
            overall_score=overall_score,
            risk_level=risk_level,
        )

        recs = self.recommendations.generate(report)
        report.recommendations = recs

        self._save_json(profiles_dir / "bug_bounty_report.json", report.model_dump(mode="json"))
        self._save_bounty_findings(project_path, report)

        logger.info(
            "BUG_BOUNTY_ENGINE_DONE routes={} apis={} secrets={} opportunities={} score={}",
            report.total_routes, report.total_apis, report.total_secrets,
            report.total_opportunities, overall_score,
        )

        return {
            "status": "completed",
            "report": report.model_dump(mode="json"),
            "routes": routes,
            "apis": api_inventory,
            "secrets": discovered_secrets,
            "opportunities": opp_dicts,
            "overall_score": overall_score,
            "risk_level": risk_level,
            "findings_generated": len(opp_dicts),
        }

    def _collect_js_urls(self, target_url: str, web_intel_dir: Path) -> list[str]:
        js_urls: list[str] = []

        web_intel = self._load_json(web_intel_dir / "js_intelligence.json") or {}
        if web_intel and web_intel.get("scripts_analyzed", 0):
            return list(set(web_intel.get("internal_urls", [])))

        try:
            import httpx
            resp = httpx.get(target_url, timeout=15.0, verify=False,
                             headers={"User-Agent": "GhostMirror-BugBounty/1.0"})
            if resp.status_code == 200:
                import re
                for match in re.finditer(r'<script\s[^>]*src=["\'](.*?)["\']', resp.text, re.IGNORECASE):
                    src = match.group(1).strip()
                    from urllib.parse import urljoin
                    absolute = urljoin(target_url, src)
                    js_urls.append(absolute)
        except Exception:
            pass

        return list(set(js_urls))

    def _save_json(self, path: Path, data: Any) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.warning("BUG_BOUNTY_SAVE_FAIL path={} error={}", path, exc)

    def _load_json(self, path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _load_json_list(self, path: Path) -> list:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_bounty_findings(self, project_path: Path, report: BugBountyReport) -> None:
        from ghostmirror.modules.bug_bounty.findings_mapper import BountyFindingsMapper
        mapper = BountyFindingsMapper()
        findings = mapper.map(report)
        if findings:
            findings_dir = project_path / "findings"
            findings_dir.mkdir(parents=True, exist_ok=True)
            path = findings_dir / "bug_bounty.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump([f.model_dump(mode="json") for f in findings], f, indent=2, ensure_ascii=False)
