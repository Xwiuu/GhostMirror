"""Tests for the Correlation Engine."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
from ghostmirror.modules.intelligence.correlation import CorrelationEngine, CorrelatedFinding


class TestCorrelationEngine:
    def test_correlated_finding_model(self) -> None:
        finding = CorrelatedFinding(
            title="Test Finding",
            description="A test finding",
            severity="HIGH",
            sources=["nmap", "cve_intelligence"],
            evidence="Port 3306, Technology: MySQL",
            recommendation="Review MySQL configuration",
        )
        assert finding.title == "Test Finding"
        assert finding.severity == "HIGH"
        assert len(finding.sources) == 2

    def test_correlated_finding_to_dict(self) -> None:
        finding = CorrelatedFinding(
            title="Test", description="Desc", severity="MEDIUM", sources=["test"]
        )
        d = finding.to_dict()
        assert d["title"] == "Test"
        assert d["severity"] == "MEDIUM"

    def test_load_nonexistent_file(self) -> None:
        result = CorrelationEngine._load_json(Path("nonexistent.json"))
        assert result is None

    def test_empty_project_path(self, tmp_path: Path) -> None:
        results = CorrelationEngine.correlate(tmp_path)
        assert results == []

    def test_no_correlation_without_data(self, tmp_path: Path) -> None:
        profiles_dir = tmp_path / "profiles"
        findings_dir = tmp_path / "findings"
        profiles_dir.mkdir()
        findings_dir.mkdir()
        nmap_data = {"open_ports": [], "services": []}
        with open(findings_dir / "nmap.json", "w") as f:
            json.dump(nmap_data, f)
        tech_data = {"technologies": []}
        with open(profiles_dir / "technology_profile.json", "w") as f:
            json.dump(tech_data, f)
        results = CorrelationEngine.correlate(tmp_path)
        assert results == []

    def test_port_tech_correlation(self, tmp_path: Path) -> None:
        profiles_dir = tmp_path / "profiles"
        findings_dir = tmp_path / "findings"
        profiles_dir.mkdir()
        findings_dir.mkdir()
        nmap_data = {"open_ports": [3306], "services": ["mysql"]}
        with open(findings_dir / "nmap.json", "w") as f:
            json.dump(nmap_data, f)
        tech_data = {"technologies": [{"name": "MySQL", "category": "DATABASE", "version": "8.0", "confidence": 1.0, "source": "test"}]}
        with open(profiles_dir / "technology_profile.json", "w") as f:
            json.dump(tech_data, f)
        vuln_data = {"matches": [{"technology": "mysql", "matched_cve": {"cve_id": "CVE-2023-1234", "severity": "HIGH", "exploit_available": True, "kev_listed": False}}]}
        with open(profiles_dir / "vulnerability_profile.json", "w") as f:
            json.dump(vuln_data, f)
        results = CorrelationEngine.correlate(tmp_path)
        assert len(results) >= 1
        assert "3306" in results[0].evidence or "mysql" in results[0].evidence.lower()
