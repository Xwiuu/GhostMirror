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

        # 6. Payload findings list
        for finding in findings_dict["payload_findings"]:
            key = (finding.title, finding.description)
            if key not in seen_keys:
                seen_keys.add(key)
                aggregated.append(finding)

        return aggregated
