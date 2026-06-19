"""Tests for Technology Intelligence SKIPPED behavior when profile is missing."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.technology_intelligence.engine import (
    TechnologyIntelligenceEngine,
)


def _make_mock_kb():
    """Create a properly structured mock KnowledgeBase."""
    kb = MagicMock()
    kb.get_technology_risk.return_value = {
        "risk_score": 5,
        "risk_level": "LOW",
        "observations": ["Test observation"],
    }
    kb.definitions = {}
    return kb


class TestTechnologyIntelligenceSkipped:
    """Verify Technology Intelligence returns SKIPPED instead of FAILED."""

    def test_skipped_when_profile_missing(self, tmp_path: Path):
        """When technology_profile.json does not exist, return SKIPPED."""
        engine = TechnologyIntelligenceEngine()
        engine.kb = _make_mock_kb()
        result = engine.analyze_project(tmp_path)
        assert result.get("status") == "skipped"
        assert "unavailable" in result.get("reason", "").lower()
        assert result.get("findings") == []
        assert result.get("risk_score") == 0

    def test_skipped_when_profile_dir_missing(self, tmp_path: Path):
        """When profiles/ directory does not exist, return SKIPPED."""
        engine = TechnologyIntelligenceEngine()
        engine.kb = _make_mock_kb()
        result = engine.analyze_project(tmp_path / "nonexistent")
        assert result.get("status") == "skipped"

    def test_skipped_message_mentions_fingerprint(self, tmp_path: Path):
        """Skipped reason should mention fingerprint step."""
        engine = TechnologyIntelligenceEngine()
        engine.kb = _make_mock_kb()
        result = engine.analyze_project(tmp_path)
        assert "fingerprint" in result.get("reason", "").lower()

    def test_returns_valid_dict_structure(self, tmp_path: Path):
        """Return value must have all expected keys."""
        engine = TechnologyIntelligenceEngine()
        engine.kb = _make_mock_kb()
        result = engine.analyze_project(tmp_path)
        expected_keys = {
            "target", "status", "reason", "findings", "risk_score",
            "risk_level", "technologies", "recommended_scans",
            "recommended_nuclei_templates", "high_value_assets",
            "potential_entry_points", "observations",
        }
        assert expected_keys.issubset(result.keys())

    def test_empty_profile_directory(self, tmp_path: Path):
        """Empty profiles/ directory should also yield SKIPPED."""
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        engine = TechnologyIntelligenceEngine()
        engine.kb = _make_mock_kb()
        result = engine.analyze_project(tmp_path)
        assert result.get("status") == "skipped"

    @patch(
        "ghostmirror.modules.technology_intelligence.recommendations.RecommendationEngine.generate_recommendations",
        return_value=([], []),
    )
    @patch.object(TechnologyIntelligenceEngine, "_generate_findings", return_value=[])
    def test_valid_profile_executes_normally(
        self, mock_gen, mock_rec, tmp_path: Path
    ):
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
        engine = TechnologyIntelligenceEngine()
        engine.kb = _make_mock_kb()
        result = engine.analyze_project(tmp_path)
        assert result.get("status") != "skipped"
        assert result.get("target") == "example.com"
