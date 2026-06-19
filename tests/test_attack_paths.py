"""Tests for the Attack Path Engine."""
from __future__ import annotations
import json
from pathlib import Path
import pytest
from ghostmirror.models.attack_path import AttackPath, AttackPathStep
from ghostmirror.modules.intelligence.attack_paths import AttackPathEngine


class TestAttackPathModels:
    def test_attack_path_step_model(self) -> None:
        step = AttackPathStep(order=1, label="WordPress Detected", detail="Version 5.8")
        assert step.order == 1
        assert step.label == "WordPress Detected"
        assert step.detail == "Version 5.8"

    def test_attack_path_model(self) -> None:
        path = AttackPath(
            path_id=1,
            title="WordPress Attack Path",
            description="Path through WordPress",
            steps=[
                AttackPathStep(order=1, label="WordPress Detected"),
                AttackPathStep(order=2, label="Known CVE", severity="HIGH"),
            ],
            risk_score=65,
            risk_level="HIGH",
            likelihood="High",
            impact="High",
            mitigations=["Update WordPress"],
        )
        assert path.path_id == 1
        assert path.risk_score == 65
        assert len(path.steps) == 2
        assert len(path.mitigations) == 1


class TestAttackPathEngine:
    def test_empty_project_path(self, tmp_path: Path) -> None:
        paths = AttackPathEngine.generate_paths(tmp_path)
        assert len(paths) >= 1
        assert paths[0].title == "No attack paths identified"

    def test_cms_attack_path_from_data(self, tmp_path: Path) -> None:
        profiles_dir = tmp_path / "profiles"
        findings_dir = tmp_path / "findings"
        profiles_dir.mkdir()
        findings_dir.mkdir()
        tech_data = {"target": "test.com", "technologies": [{"name": "WordPress", "category": "CMS", "version": "5.8", "confidence": 1.0, "source": "test"}]}
        with open(profiles_dir / "technology_profile.json", "w") as f:
            json.dump(tech_data, f)
        vuln_data = {"matches": [{"technology": "wordpress", "risk_level": "CRITICAL", "matched_cve": {"cve_id": "CVE-2021-1234", "severity": "CRITICAL", "exploit_available": True}}]}
        with open(profiles_dir / "vulnerability_profile.json", "w") as f:
            json.dump(vuln_data, f)
        paths = AttackPathEngine.generate_paths(tmp_path)
        wordpress_paths = [p for p in paths if "wordpress" in p.title.lower()]
        assert len(wordpress_paths) >= 1
        wp = wordpress_paths[0]
        assert wp.risk_level in ("HIGH", "CRITICAL")
        assert any("CVEs" in s.label or "Known" in s.label for s in wp.steps)

    def test_service_attack_path(self, tmp_path: Path) -> None:
        profiles_dir = tmp_path / "profiles"
        findings_dir = tmp_path / "findings"
        profiles_dir.mkdir()
        findings_dir.mkdir()
        nmap_data = {"open_ports": [22], "services": ["ssh"]}
        with open(findings_dir / "nmap.json", "w") as f:
            json.dump(nmap_data, f)
        paths = AttackPathEngine.generate_paths(tmp_path)
        ssh_paths = [p for p in paths if "SSH" in p.title]
        assert len(ssh_paths) >= 1

    def test_database_attack_path(self, tmp_path: Path) -> None:
        profiles_dir = tmp_path / "profiles"
        findings_dir = tmp_path / "findings"
        profiles_dir.mkdir()
        findings_dir.mkdir()
        tech_data = {"target": "test.com", "technologies": [{"name": "MySQL", "category": "DATABASE", "confidence": 1.0, "source": "test"}]}
        with open(profiles_dir / "technology_profile.json", "w") as f:
            json.dump(tech_data, f)
        paths = AttackPathEngine.generate_paths(tmp_path)
        db_paths = [p for p in paths if "mysql" in p.title.lower()]
        assert len(db_paths) >= 1
