"""Collector to load all findings and profiles from a project's storage directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.models.finding import FindingModel, ScanResultModel

logger = get_logger()


class ReportCollector:
    """Loads and validates all project findings and risk profiles for report generation."""

    def __init__(self, project_path: Path | str) -> None:
        self.project_path = Path(project_path)
        self.findings_dir = self.project_path / "findings"
        self.profiles_dir = self.project_path / "profiles"

    def collect(self) -> dict[str, Any]:
        """Loads all project data, returning a dictionary of findings and profiles."""
        logger.info("COLLECTING_REPORT_DATA project={}", self.project_path.name)

        data = {
            "findings": {
                "headers": self._load_scan_result("headers"),
                "ssl": self._load_scan_result("ssl"),
                "nmap": self._load_scan_result("nmap"),
                "fingerprint": self._load_scan_result("fingerprint"),
                "technology_intelligence": self._load_json_dict(
                    self.findings_dir / "technology_intelligence.json"
                ),
                "cve_findings": self._load_finding_list(
                    self.findings_dir / "cve_findings.json"
                ),
                "nuclei_findings": self._load_finding_list(
                    self.findings_dir / "nuclei_findings.json"
                ),
                "owasp_findings": self._load_finding_list(
                    self.findings_dir / "owasp_findings.json"
                ),
                "payload_findings": self._load_finding_list(
                    self.findings_dir / "payload_findings.json"
                ),
            },
            "profiles": {
                "technology_profile": self._load_json_dict(
                    self.profiles_dir / "technology_profile.json"
                ),
                "attack_surface_profile": self._load_json_dict(
                    self.profiles_dir / "attack_surface_profile.json"
                ),
                "risk_profile": self._load_json_dict(
                    self.profiles_dir / "risk_profile.json"
                ),
                "vulnerability_profile": self._load_json_dict(
                    self.profiles_dir / "vulnerability_profile.json"
                ),
                "nuclei_profile": self._load_json_dict(
                    self.profiles_dir / "nuclei_profile.json"
                ),
                "owasp_profile": self._load_json_dict(
                    self.profiles_dir / "owasp_profile.json"
                ),
                "payload_profile": self._load_json_dict(
                    self.profiles_dir / "payload_profile.json"
                ),
                "intelligence_report": self._load_json_dict(
                    self.profiles_dir / "intelligence_report.json"
                ),
                "risk_matrix": self._load_json_dict(
                    self.profiles_dir / "risk_matrix.json"
                ),
                "attack_paths": self._load_json_list(
                    self.profiles_dir / "attack_paths.json"
                ),
                "executive_summary": self._load_json_dict(
                    self.profiles_dir / "executive_summary.json"
                ),
                "waf_profile": self._load_json_dict(
                    self.profiles_dir / "waf_profile.json"
                ),
                "cdn_profile": self._load_json_dict(
                    self.profiles_dir / "cdn_profile.json"
                ),
                "hosting_profile": self._load_json_dict(
                    self.profiles_dir / "hosting_profile.json"
                ),
                "dns_profile": self._load_json_dict(
                    self.profiles_dir / "dns_profile.json"
                ),
                "vulnerability_intelligence_report": self._load_json_dict(
                    self.profiles_dir / "vulnerability_intelligence" / "vulnerability_intelligence_report.json"
                ),
                "vulnerability_priority": self._load_json_list(
                    self.profiles_dir / "vulnerability_intelligence" / "vulnerability_priority.json"
                ),
                "epss_profile": self._load_json_list(
                    self.profiles_dir / "vulnerability_intelligence" / "epss_profile.json"
                ),
                "kev_profile": self._load_json_list(
                    self.profiles_dir / "vulnerability_intelligence" / "kev_profile.json"
                ),
                "exploit_profile": self._load_json_list(
                    self.profiles_dir / "vulnerability_intelligence" / "exploit_profile.json"
                ),
                "attack_opportunities": self._load_json_list(
                    self.profiles_dir / "vulnerability_intelligence" / "attack_opportunities.json"
                ),
                "finding_intelligence_report": self._load_json_dict(
                    self.profiles_dir / "finding_intelligence_report.json"
                ),
                "enriched_findings": self._load_json_list(
                    self.profiles_dir / "enriched_findings.json"
                ),
                "top_findings": self._load_json_list(
                    self.profiles_dir / "top_findings.json"
                ),
                "quick_wins": self._load_json_list(
                    self.profiles_dir / "quick_wins.json"
                ),
                # Web Intelligence
                "web_intelligence_report": self._load_json_dict(
                    self.profiles_dir / "web_intelligence" / "web_intelligence_report.json"
                ),
                "web_endpoint_inventory": self._load_json_list(
                    self.profiles_dir / "web_intelligence" / "endpoint_inventory.json"
                ),
                "web_parameter_inventory": self._load_json_list(
                    self.profiles_dir / "web_intelligence" / "parameter_inventory.json"
                ),
                "web_js_intelligence": self._load_json_dict(
                    self.profiles_dir / "web_intelligence" / "js_intelligence.json"
                ),
                "web_auth_profile": self._load_json_dict(
                    self.profiles_dir / "web_intelligence" / "auth_profile.json"
                ),
                "web_indicators": self._load_json_list(
                    self.profiles_dir / "web_intelligence" / "web_indicators.json"
                ),
                "web_correlations": self._load_json_list(
                    self.profiles_dir / "web_intelligence" / "correlation_results.json"
                ),
                "web_opportunities": self._load_json_list(
                    self.profiles_dir / "web_intelligence" / "opportunity_scores.json"
                ),
                "web_business_logic": self._load_json_list(
                    self.profiles_dir / "web_intelligence" / "business_logic.json"
                ),
                "web_recommendations": self._load_json_list(
                    self.profiles_dir / "web_intelligence" / "web_recommendations.json"
                ),
                "web_attack_surface": self._load_json_dict(
                    self.profiles_dir / "web_intelligence" / "attack_surface.json"
                ),
                # Bug Bounty
                "bug_bounty_report": self._load_json_dict(
                    self.profiles_dir / "bug_bounty" / "bug_bounty_report.json"
                ),
                "bug_bounty_routes": self._load_json_list(
                    self.profiles_dir / "bug_bounty" / "headless_routes.json"
                ),
                "bug_bounty_apis": self._load_json_list(
                    self.profiles_dir / "bug_bounty" / "api_inventory.json"
                ),
                "bug_bounty_secrets": self._load_json_list(
                    self.profiles_dir / "bug_bounty" / "secrets_discovery.json"
                ),
                "bug_bounty_opportunities": self._load_json_list(
                    self.profiles_dir / "bug_bounty" / "bug_bounty_opportunities.json"
                ),
                "bug_bounty_js_bundles": self._load_json_list(
                    self.profiles_dir / "bug_bounty" / "js_bundle_profile.json"
                ),
                "bug_bounty_sourcemaps": self._load_json_list(
                    self.profiles_dir / "bug_bounty" / "sourcemap_profile.json"
                ),
                "bug_bounty_subdomains": self._load_json_list(
                    self.profiles_dir / "bug_bounty" / "subdomain_profile.json"
                ),
                "bug_bounty_interesting_files": self._load_json_list(
                    self.profiles_dir / "bug_bounty" / "interesting_files.json"
                ),
                # API Security Intelligence
                "api_security_report": self._load_json_dict(
                    self.profiles_dir / "api_security" / "api_security_report.json"
                ),
                "api_inventory": self._load_json_dict(
                    self.profiles_dir / "api_security" / "api_inventory.json"
                ),
                "swagger_profile": self._load_json_dict(
                    self.profiles_dir / "api_security" / "swagger_profile.json"
                ),
                "graphql_profile": self._load_json_dict(
                    self.profiles_dir / "api_security" / "graphql_profile.json"
                ),
                "jwt_profile": self._load_json_dict(
                    self.profiles_dir / "api_security" / "jwt_profile.json"
                ),
                "oauth_profile": self._load_json_dict(
                    self.profiles_dir / "api_security" / "oauth_profile.json"
                ),
                "object_inventory": self._load_json_list(
                    self.profiles_dir / "api_security" / "object_inventory.json"
                ),
                "rate_limit_profile": self._load_json_dict(
                    self.profiles_dir / "api_security" / "rate_limit_profile.json"
                ),
                "api_attack_surface": self._load_json_dict(
                    self.profiles_dir / "api_security" / "api_attack_surface.json"
                ),
                "api_bola_indicators": self._load_json_list(
                    self.profiles_dir / "api_security" / "bola_indicators.json"
                ),
                "api_bfla_indicators": self._load_json_list(
                    self.profiles_dir / "api_security" / "bfla_indicators.json"
                ),
                "api_mass_assignment_indicators": self._load_json_list(
                    self.profiles_dir / "api_security" / "mass_assignment_indicators.json"
                ),
                "api_correlations": self._load_json_list(
                    self.profiles_dir / "api_security" / "api_correlations.json"
                ),
                "api_opportunities": self._load_json_list(
                    self.profiles_dir / "api_security" / "api_opportunities.json"
                ),
                "api_recommendations": self._load_json_list(
                    self.profiles_dir / "api_security" / "api_recommendations.json"
                ),
                # Zero-Day Hypothesis Engine
                "zero_day_report": self._load_json_dict(
                    self.profiles_dir / "zero_day" / "zero_day_report.json"
                ),
                "zero_day_anomalies": self._load_json_list(
                    self.profiles_dir / "zero_day" / "anomalies.json"
                ),
                "zero_day_attack_chains": self._load_json_list(
                    self.profiles_dir / "zero_day" / "attack_chains.json"
                ),
                "zero_day_hypotheses": self._load_json_list(
                    self.profiles_dir / "zero_day" / "hypotheses.json"
                ),
                # Attack Chain Intelligence
                "attack_chain_report": self._load_json_dict(
                    self.profiles_dir / "attack_chain" / "attack_chain_report.json"
                ),
                "attack_chain_graph": self._load_json_dict(
                    self.profiles_dir / "attack_chain" / "attack_graph.json"
                ),
                "attack_chain_chains": self._load_json_list(
                    self.profiles_dir / "attack_chain" / "chains.json"
                ),
                "attack_chain_priorities": self._load_json_list(
                    self.profiles_dir / "attack_chain" / "attack_chain_priorities.json"
                ),
                "attack_chain_signals": self._load_json_list(
                    self.profiles_dir / "attack_chain" / "signals.json"
                ),
                "zero_day_opportunities": self._load_json_list(
                    self.profiles_dir / "zero_day" / "business_logic_opportunities.json"
                ),
                "zero_day_research_queue": self._load_json_list(
                    self.profiles_dir / "zero_day" / "research_queue.json"
                ),
                # HackerOne / Bug Bounty Reporting
                "bounty_report": self._load_json_dict(
                    Path("reports") / "bounty" / "bounty_report.json"
                ),
                # Pentester Assistant
                "assistant_report": self._load_json_dict(
                    self.profiles_dir / "assistant" / "assistant_report.json"
                ),
                "assistant_priorities": self._load_json_dict(
                    self.profiles_dir / "assistant" / "assistant_priorities.json"
                ),
            },
        }

        # Try to load nuclei standard scan result if nuclei_findings is empty
        if not data["findings"]["nuclei_findings"]:
            nuclei_scan_res = self._load_scan_result("nuclei")
            if nuclei_scan_res:
                data["findings"]["nuclei_findings"] = nuclei_scan_res.findings

        # Aggregate all unique findings for consolidated score and display
        data["all_findings"] = self._aggregate_findings(data["findings"])

        # Load execution timeline for module-level reporting
        timeline_path = self.project_path / "execution" / "full_scan_timeline.json"
        if timeline_path.exists():
            try:
                with open(timeline_path, "r", encoding="utf-8") as f:
                    data["timeline"] = json.load(f)
                data["pipeline_summary"] = self._compute_pipeline_summary(
                    data["timeline"]
                )
            except Exception as exc:
                logger.warning("Failed to load timeline {}: {}", timeline_path, exc)
                data["timeline"] = {}
                data["pipeline_summary"] = {}

        return data

    def _compute_pipeline_summary(
        self, timeline: dict
    ) -> dict[str, int]:
        """Compute pipeline execution counts from the timeline."""
        steps = timeline.get("steps", [])
        executed = sum(1 for s in steps if s.get("status") == "completed")
        skipped = sum(1 for s in steps if s.get("status") == "skipped")
        failed = sum(1 for s in steps if s.get("status") == "failed")
        warnings = sum(1 for s in steps if s.get("status") == "warning")
        return {
            "executed": executed,
            "skipped": skipped,
            "failed": failed,
            "warnings": warnings,
        }

    def _load_scan_result(self, name: str) -> ScanResultModel | None:
        file_path = self.findings_dir / f"{name.lower()}.json"
        if not file_path.exists():
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return ScanResultModel.model_validate(raw)
        except Exception as exc:
            logger.warning("Failed to load scan result {}: {}", name, exc)
            return None

    def _load_json_dict(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed to load JSON {}: {}", path, exc)
            return None

    def _load_json_list(self, path: Path) -> list[Any]:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception as exc:
            logger.warning("Failed to load JSON list {}: {}", path, exc)
            return []

    def _load_finding_list(self, path: Path) -> list[FindingModel]:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw_list = json.load(f)
            if isinstance(raw_list, list):
                return [FindingModel.model_validate(item) for item in raw_list]
        except Exception as exc:
            logger.warning("Failed to load finding list {}: {}", path, exc)
        return []

    def _aggregate_findings(self, findings_dict: dict[str, Any]) -> list[FindingModel]:
        """Collect and deduplicate findings across all scanner outputs."""
        aggregated: list[FindingModel] = []
        seen_keys: set[tuple[str, str]] = set()

        # 1. Standard scanner results
        for scanner_name in ["headers", "ssl", "nmap", "fingerprint"]:
            res = findings_dict[scanner_name]
            if res and res.findings:
                for finding in res.findings:
                    key = (finding.title, finding.description)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        aggregated.append(finding)

        # 2. Technology Intelligence findings
        tech_intel = findings_dict["technology_intelligence"]
        if tech_intel and "findings" in tech_intel:
            for item in tech_intel["findings"]:
                try:
                    finding = FindingModel.model_validate(item)
                    key = (finding.title, finding.description)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        aggregated.append(finding)
                except Exception:
                    pass

        # 3. CVE findings list
        for finding in findings_dict["cve_findings"]:
            key = (finding.title, finding.description)
            if key not in seen_keys:
                seen_keys.add(key)
                aggregated.append(finding)

        # 4. Nuclei findings list
        for finding in findings_dict["nuclei_findings"]:
            key = (finding.title, finding.description)
            if key not in seen_keys:
                seen_keys.add(key)
                aggregated.append(finding)

        # 5. OWASP findings list
        for finding in findings_dict["owasp_findings"]:
            key = (finding.title, finding.description)
            if key not in seen_keys:
                seen_keys.add(key)
                aggregated.append(finding)

        # 6. Intelligence findings list
        intel_findings = self._load_finding_list(
            self.findings_dir / "intelligence_findings.json"
        )
        for finding in intel_findings:
            key = (finding.title, finding.description)
            if key not in seen_keys:
                seen_keys.add(key)
                aggregated.append(finding)

        # 7. Payload findings list
        for finding in findings_dict["payload_findings"]:
            key = (finding.title, finding.description)
            if key not in seen_keys:
                seen_keys.add(key)
                aggregated.append(finding)

        return aggregated

