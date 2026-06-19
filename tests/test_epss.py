from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.models.epss_profile import EPSSProfileModel
from ghostmirror.modules.vulnerability_intelligence.epss_engine import EPSSEngine


@pytest.fixture()
def epss_knowledge_dir(tmp_path: Path) -> Path:
    kd = tmp_path / "knowledge" / "vulnerability_intelligence"
    kd.mkdir(parents=True)
    data = {
        "CVE-2021-41773": {"epss_score": 0.93210, "percentile": 99.21},
        "CVE-2022-22965": {"epss_score": 0.97120, "percentile": 99.67},
    }
    with open(kd / "epss_scores.json", "w") as f:
        json.dump(data, f)
    return kd.parent  # Return knowledge/ directory


class TestEPSSEngine:
    def test_load_scores(self, epss_knowledge_dir: Path):
        engine = EPSSEngine(knowledge_dir=epss_knowledge_dir)
        assert len(engine._scores) == 2
        assert "CVE-2021-41773" in engine._scores

    def test_get_score_known(self, epss_knowledge_dir: Path):
        engine = EPSSEngine(knowledge_dir=epss_knowledge_dir)
        result = engine.get_score("CVE-2021-41773")
        assert result.cve == "CVE-2021-41773"
        assert result.epss_score == 0.93210
        assert result.percentile == 99.21
        assert result.classification == "CRITICAL"

    def test_get_score_unknown_mocked(self, epss_knowledge_dir: Path):
        engine = EPSSEngine(knowledge_dir=epss_knowledge_dir)
        result = engine.get_score("CVE-UNKNOWN-001", severity="CRITICAL")
        assert result.cve == "CVE-UNKNOWN-001"
        assert 0.85 <= result.epss_score <= 0.99
        assert result.classification == "CRITICAL"

    def test_get_score_unknown_low_severity(self, epss_knowledge_dir: Path):
        engine = EPSSEngine(knowledge_dir=epss_knowledge_dir)
        result = engine.get_score("CVE-UNKNOWN-002", severity="LOW")
        assert result.cve == "CVE-UNKNOWN-002"
        assert 0.01 <= result.epss_score <= 0.14
        assert result.classification == "VERY_LOW"

    def test_get_scores_batch(self, epss_knowledge_dir: Path):
        engine = EPSSEngine(knowledge_dir=epss_knowledge_dir)
        results = engine.get_scores_batch(["CVE-2021-41773", "CVE-2022-22965", "CVE-UNKNOWN"])
        assert len(results) == 3
        assert results[0].cve == "CVE-2021-41773"

    def test_classify_boundaries(self):
        assert EPSSProfileModel.classify(0.0) == "VERY_LOW"
        assert EPSSProfileModel.classify(0.20) == "VERY_LOW"
        assert EPSSProfileModel.classify(0.21) == "LOW"
        assert EPSSProfileModel.classify(0.40) == "LOW"
        assert EPSSProfileModel.classify(0.41) == "MEDIUM"
        assert EPSSProfileModel.classify(0.60) == "MEDIUM"
        assert EPSSProfileModel.classify(0.61) == "HIGH"
        assert EPSSProfileModel.classify(0.80) == "HIGH"
        assert EPSSProfileModel.classify(0.81) == "CRITICAL"
        assert EPSSProfileModel.classify(1.0) == "CRITICAL"

    def test_epss_model_creation(self):
        model = EPSSProfileModel(
            cve="CVE-2021-41773",
            epss_score=0.9321,
            percentile=99.21,
            classification="CRITICAL",
        )
        assert model.cve == "CVE-2021-41773"
        assert model.epss_score == 0.9321
        assert model.percentile == 99.21

    def test_epss_model_serialization(self):
        model = EPSSProfileModel(
            cve="CVE-2021-41773",
            epss_score=0.5,
            percentile=50.0,
            classification="MEDIUM",
        )
        data = model.model_dump(mode="json")
        assert data["cve"] == "CVE-2021-41773"
        assert data["epss_score"] == 0.5

    def test_empty_knowledge_dir(self, tmp_path: Path):
        kd = tmp_path / "knowledge"
        kd.mkdir()
        engine = EPSSEngine(knowledge_dir=kd)
        assert len(engine._scores) == 0
        result = engine.get_score("CVE-TEST", severity="HIGH")
        assert result.epss_score > 0
