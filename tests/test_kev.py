from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.vulnerability_intelligence.kev_engine import KEVEngine


@pytest.fixture()
def kev_knowledge_dir(tmp_path: Path) -> Path:
    kd = tmp_path / "knowledge" / "vulnerability_intelligence"
    kd.mkdir(parents=True)
    data = [
        {
            "cve_id": "CVE-2021-41773",
            "kev": True,
            "ransomware_usage": False,
            "known_exploitation": True,
            "date_added": "2021-10-11",
            "vendor_project": "Apache",
            "product": "HTTP Server",
            "short_description": "Apache HTTP Server path traversal",
        },
        {
            "cve_id": "CVE-2021-44228",
            "kev": True,
            "ransomware_usage": True,
            "known_exploitation": True,
            "date_added": "2021-12-10",
            "vendor_project": "Apache",
            "product": "Log4j",
            "short_description": "Log4j RCE",
        },
    ]
    with open(kd / "kev_catalog.json", "w") as f:
        json.dump(data, f)
    return kd.parent  # Return knowledge/ directory


class TestKEVEngine:
    def test_load_catalog(self, kev_knowledge_dir: Path):
        engine = KEVEngine(knowledge_dir=kev_knowledge_dir)
        assert len(engine._catalog) == 2
        assert "CVE-2021-41773" in engine._catalog

    def test_check_cve_kev_true(self, kev_knowledge_dir: Path):
        engine = KEVEngine(knowledge_dir=kev_knowledge_dir)
        result = engine.check_cve("CVE-2021-41773")
        assert result.kev is True
        assert result.cve == "CVE-2021-41773"
        assert result.ransomware_usage is False
        assert result.known_exploitation is True

    def test_check_cve_kev_true_ransomware(self, kev_knowledge_dir: Path):
        engine = KEVEngine(knowledge_dir=kev_knowledge_dir)
        result = engine.check_cve("CVE-2021-44228")
        assert result.kev is True
        assert result.ransomware_usage is True

    def test_check_cve_not_in_kev(self, kev_knowledge_dir: Path):
        engine = KEVEngine(knowledge_dir=kev_knowledge_dir)
        result = engine.check_cve("CVE-2023-00000")
        assert result.kev is False
        assert result.ransomware_usage is False
        assert result.known_exploitation is False

    def test_check_batch(self, kev_knowledge_dir: Path):
        engine = KEVEngine(knowledge_dir=kev_knowledge_dir)
        results = engine.check_batch(["CVE-2021-41773", "CVE-2021-44228", "CVE-UNKNOWN"])
        assert len(results) == 3
        assert results[0].kev is True
        assert results[1].kev is True
        assert results[2].kev is False

    def test_check_batch_empty(self, kev_knowledge_dir: Path):
        engine = KEVEngine(knowledge_dir=kev_knowledge_dir)
        results = engine.check_batch([])
        assert results == []

    def test_empty_knowledge_dir(self, tmp_path: Path):
        engine = KEVEngine(knowledge_dir=tmp_path)
        assert len(engine._catalog) == 0
        result = engine.check_cve("CVE-TEST")
        assert result.kev is False

    def test_kev_model_serialization(self, kev_knowledge_dir: Path):
        engine = KEVEngine(knowledge_dir=kev_knowledge_dir)
        result = engine.check_cve("CVE-2021-41773")
        data = result.model_dump(mode="json")
        assert data["kev"] is True
        assert data["vendor_project"] == "Apache"

    def test_corrupted_json(self, tmp_path: Path):
        kd = tmp_path / "knowledge" / "vulnerability_intelligence"
        kd.mkdir(parents=True)
        with open(kd / "kev_catalog.json", "w") as f:
            f.write("not valid json")
        engine = KEVEngine(knowledge_dir=kd.parent)
        assert len(engine._catalog) == 0
