"""Tests for CVE Intelligence SKIPPED behavior when profile is missing."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.cve_intelligence.engine import CVEIntelligenceEngine


def _make_mock_kb():
    """Create a properly structured mock CVEKnowledgeBase."""
    kb = MagicMock()
    kb.aliases_path = Path("/fake/aliases.json")
    kb.definitions = {}
    kb.nuclei_map = {}
    return kb


class TestCVEIntelligenceSkipped:
    """Verify CVE Intelligence returns SKIPPED instead of FAILED."""

    def test_skipped_when_profile_missing(self, tmp_path: Path):
        """When technology_profile.json does not exist, return SKIPPED."""
        engine = CVEIntelligenceEngine()
        engine.kb = _make_mock_kb()
        engine.matcher = MagicMock()
        result = engine.analyze_project(tmp_path)
        assert result.get("status") == "skipped"
        assert "unavailable" in result.get("reason", "").lower()
        assert result.get("total_cves") == 0

    def test_skipped_message_mentions_tech_intel(self, tmp_path: Path):
        """Skipped reason should mention Technology Intelligence."""
        engine = CVEIntelligenceEngine()
        engine.kb = _make_mock_kb()
        engine.matcher = MagicMock()
        result = engine.analyze_project(tmp_path)
        assert "technology" in result.get("reason", "").lower()

    def test_returns_valid_dict_structure(self, tmp_path: Path):
        """Return value must have all expected keys."""
        engine = CVEIntelligenceEngine()
        engine.kb = _make_mock_kb()
        engine.matcher = MagicMock()
        result = engine.analyze_project(tmp_path)
        expected_keys = {
            "target", "status", "reason", "findings", "total_cves",
            "critical_count", "high_count", "medium_count", "low_count",
            "overall_vulnerability_score", "overall_risk_level",
        }
        assert expected_keys.issubset(result.keys())

    def test_empty_profile_directory(self, tmp_path: Path):
        """Empty profiles/ directory should yield SKIPPED."""
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        engine = CVEIntelligenceEngine()
        engine.kb = _make_mock_kb()
        engine.matcher = MagicMock()
        result = engine.analyze_project(tmp_path)
        assert result.get("status") == "skipped"

    @patch.object(CVEIntelligenceEngine, "_generate_findings", return_value=[])
    def test_valid_profile_executes_normally(self, mock_gen, tmp_path: Path):
        """When technology_profile.json exists, engine should run normally."""
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        tech_profile = {
            "target": "example.com",
            "technologies": [
                {
                    "name": "Nginx",
                    "category": "Web Server",
                    "version": "1.18",
                    "confidence": 0.9,
                    "source": "whatweb",
                }
            ],
        }
        with open(profiles_dir / "technology_profile.json", "w") as f:
            json.dump(tech_profile, f)
        engine = CVEIntelligenceEngine()
        engine.kb = _make_mock_kb()
        engine.matcher = MagicMock()
        engine.matcher.match_technology.return_value = []
        result = engine.analyze_project(tmp_path)
        assert result.get("status") != "skipped"
