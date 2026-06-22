from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.zero_day.differential_engine import DifferentialEngine


class TestDifferentialEngine:
    def test_init(self):
        engine = DifferentialEngine()
        assert engine.signals == []

    def test_analyze_no_data(self, tmp_path: Path):
        engine = DifferentialEngine()
        result = engine.analyze(tmp_path)
        assert result == []

    def test_extract_base_path(self):
        engine = DifferentialEngine()
        assert engine._extract_base_path("https://example.com/api/users") == "https://example.com/api/users"
        assert engine._extract_base_path("") is None
        assert engine._extract_base_path(None) is None

    def test_group_endpoints_empty(self):
        engine = DifferentialEngine()
        result = engine._group_endpoints([])
        assert result == {}

    def test_group_endpoints_single(self):
        engine = DifferentialEngine()
        eps = [{"url": "https://example.com/api/users", "method": "GET", "_source": "test"}]
        result = engine._group_endpoints(eps)
        assert len(result) >= 1

    def test_compare_variants_status_diff(self):
        engine = DifferentialEngine()
        variants = [
            {"url": "https://example.com/api/resource", "method": "GET", "status_code": 200, "_source": "test"},
            {"url": "https://example.com/api/resource/", "method": "GET", "status_code": 403, "_source": "test"},
        ]
        signals = engine._compare_variants("/api/resource", variants)
        assert any(s["signal_type"] == "differential_status" for s in signals)

    def test_compare_variants_size_diff(self):
        engine = DifferentialEngine()
        variants = [
            {"url": "https://example.com/api/resource", "method": "GET", "status_code": 200, "size": 100, "_source": "test"},
            {"url": "https://example.com/api/resource?id=1", "method": "GET", "status_code": 200, "size": 5000, "_source": "test"},
        ]
        signals = engine._compare_variants("/api/resource", variants)
        assert any(s["signal_type"] == "differential_size" for s in signals)

    def test_compare_variants_content_type_diff(self):
        engine = DifferentialEngine()
        variants = [
            {"url": "https://example.com/api/resource", "method": "GET", "status_code": 200, "content_type": "application/json", "_source": "test"},
            {"url": "https://example.com/api/resource?format=xml", "method": "GET", "status_code": 200, "content_type": "text/html", "_source": "test"},
        ]
        signals = engine._compare_variants("/api/resource", variants)
        assert any(s["signal_type"] == "differential_content_type" for s in signals)

    def test_compare_variants_no_diff(self):
        engine = DifferentialEngine()
        variants = [
            {"url": "https://example.com/api/resource", "method": "GET", "status_code": 200, "size": 100, "_source": "test"},
            {"url": "https://example.com/api/resource/", "method": "GET", "status_code": 200, "size": 100, "_source": "test"},
        ]
        signals = engine._compare_variants("/api/resource", variants)
        assert len(signals) == 0

    def test_compare_variants_single_no_comparison(self):
        engine = DifferentialEngine()
        signals = engine._compare_variants("/api/resource", [{"url": "https://example.com/api/resource", "method": "GET", "_source": "test"}])
        assert len(signals) == 0

    def test_load_json_list_missing(self, tmp_path: Path):
        engine = DifferentialEngine()
        result = engine._load_json_list(tmp_path / "nonexistent.json")
        assert result == []

    def test_load_json_list_valid(self, tmp_path: Path):
        engine = DifferentialEngine()
        p = tmp_path / "data.json"
        with open(p, "w") as f:
            json.dump([1, 2, 3], f)
        result = engine._load_json_list(p)
        assert result == [1, 2, 3]

    def test_load_json_dict_missing(self, tmp_path: Path):
        engine = DifferentialEngine()
        result = engine._load_json_dict(tmp_path / "nonexistent.json")
        assert result is None

    def test_load_json_dict_valid(self, tmp_path: Path):
        engine = DifferentialEngine()
        p = tmp_path / "data.json"
        with open(p, "w") as f:
            json.dump({"key": "value"}, f)
        result = engine._load_json_dict(p)
        assert result == {"key": "value"}

    def test_analyze_with_api_data(self, tmp_path: Path):
        web_dir = tmp_path / "profiles" / "web_intelligence"
        web_dir.mkdir(parents=True, exist_ok=True)
        with open(web_dir / "endpoint_inventory.json", "w") as f:
            json.dump([{"url": "https://example.com/api/resource", "method": "GET", "status_code": 200}], f)
        engine = DifferentialEngine()
        result = engine.analyze(tmp_path)
        assert result == []

    def test_analyze_with_different_variants(self, tmp_path: Path):
        web_dir = tmp_path / "profiles" / "web_intelligence"
        web_dir.mkdir(parents=True, exist_ok=True)
        with open(web_dir / "endpoint_inventory.json", "w") as f:
            json.dump([
                {"url": "https://example.com/api/resource", "method": "GET", "status_code": 200, "size": 100},
                {"url": "https://example.com/api/resource/", "method": "GET", "status_code": 403, "size": 50},
            ], f)
        engine = DifferentialEngine()
        result = engine.analyze(tmp_path)
        assert len(result) >= 1

    def test_analyze_with_api_inventory_dict(self, tmp_path: Path):
        api_dir = tmp_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "api_inventory.json", "w") as f:
            json.dump({"endpoints": [{"url": "https://example.com/api/resource", "method": "GET", "status_code": 200}]}, f)
        engine = DifferentialEngine()
        result = engine.analyze(tmp_path)
        assert result == []
