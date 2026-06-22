from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.zero_day.anomaly_engine import AnomalyEngine


class TestAnomalyEngine:
    def test_init(self):
        engine = AnomalyEngine()
        assert engine.anomalies == []

    def test_analyze_no_endpoints(self, tmp_path: Path):
        engine = AnomalyEngine()
        result = engine.analyze(tmp_path)
        assert result == []

    def test_detect_rare_endpoints_admin(self):
        engine = AnomalyEngine()
        endpoints = [
            {"url": "https://example.com/admin", "method": "GET", "_source": "test"},
        ]
        signals = engine._detect_rare_endpoints(endpoints)
        assert len(signals) >= 1
        assert signals[0]["signal_type"] == "rare_endpoint"
        assert signals[0]["observed"] == "admin"

    def test_detect_rare_endpoints_multiple(self):
        engine = AnomalyEngine()
        endpoints = [
            {"url": "https://example.com/admin", "method": "GET", "_source": "test"},
            {"url": "https://example.com/.env", "method": "GET", "_source": "test"},
            {"url": "https://example.com/debug", "method": "GET", "_source": "test"},
        ]
        signals = engine._detect_rare_endpoints(endpoints)
        assert len(signals) >= 3

    def test_detect_rare_endpoints_no_match(self):
        engine = AnomalyEngine()
        endpoints = [
            {"url": "https://example.com/api/users", "method": "GET", "_source": "test"},
        ]
        signals = engine._detect_rare_endpoints(endpoints)
        assert len(signals) == 0

    def test_detect_status_anomalies_500(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/error", "status_code": 500, "method": "GET", "_source": "test"}]
        signals = engine._detect_status_anomalies(endpoints)
        assert len(signals) == 1
        assert signals[0]["severity"] == "HIGH"

    def test_detect_status_anomalies_404(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/notfound", "status": 404, "method": "GET", "_source": "test"}]
        signals = engine._detect_status_anomalies(endpoints)
        assert len(signals) == 1

    def test_detect_status_anomalies_200_ignored(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/ok", "status_code": 200, "method": "GET", "_source": "test"}]
        signals = engine._detect_status_anomalies(endpoints)
        assert len(signals) == 0

    def test_detect_content_anomalies(self):
        engine = AnomalyEngine()
        endpoints = [
            {"url": "https://example.com/a", "size": 100, "method": "GET", "_source": "test"},
            {"url": "https://example.com/b", "size": 200, "method": "GET", "_source": "test"},
            {"url": "https://example.com/c", "size": 150, "method": "GET", "_source": "test"},
            {"url": "https://example.com/d", "size": 180, "method": "GET", "_source": "test"},
            {"url": "https://example.com/e", "size": 220, "method": "GET", "_source": "test"},
            {"url": "https://example.com/huge", "size": 500000, "method": "GET", "_source": "test"},
        ]
        signals = engine._detect_content_anomalies(endpoints)
        assert len(signals) >= 1

    def test_detect_content_anomalies_no_sizes(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/test", "method": "GET", "_source": "test"}]
        signals = engine._detect_content_anomalies(endpoints)
        assert len(signals) == 0

    def test_detect_rare_headers_debug(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/test", "method": "GET", "_source": "test", "headers": {"X-Debug": "true"}}]
        signals = engine._detect_rare_headers(endpoints)
        assert len(signals) == 1

    def test_detect_sensitive_headers(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/test", "method": "GET", "_source": "test", "headers": {"X-Api-Key": "secret"}}]
        signals = engine._detect_rare_headers(endpoints)
        assert any(s["signal_type"] == "sensitive_header" for s in signals)

    def test_detect_rare_headers_no_match(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/test", "method": "GET", "_source": "test", "headers": {"Content-Type": "application/json"}}]
        signals = engine._detect_rare_headers(endpoints)
        assert len(signals) == 0

    def test_detect_rare_headers_list_format(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/test", "method": "GET", "_source": "test", "response_headers": [{"name": "X-Debug", "value": "true"}]}]
        signals = engine._detect_rare_headers(endpoints)
        assert len(signals) >= 1

    def test_group_signals_empty(self):
        engine = AnomalyEngine()
        result = engine._group_signals([])
        assert result == []

    def test_group_signals_single(self):
        engine = AnomalyEngine()
        signals = [{"endpoint": "/admin", "signal_type": "rare_endpoint", "severity": "MEDIUM", "description": "test", "source": "test", "method": "GET", "expected": "x", "observed": "y"}]
        result = engine._group_signals(signals)
        assert len(result) == 1
        assert result[0]["score"] > 0

    def test_group_signals_multiple(self):
        engine = AnomalyEngine()
        signals = [
            {"endpoint": "/admin", "signal_type": "rare_endpoint", "severity": "MEDIUM", "description": "test1", "source": "test", "method": "GET", "expected": "x", "observed": "y"},
            {"endpoint": "/admin", "signal_type": "rare_endpoint", "severity": "HIGH", "description": "test2", "source": "test", "method": "GET", "expected": "x", "observed": "y"},
            {"endpoint": "/admin", "signal_type": "rare_endpoint", "severity": "LOW", "description": "test3", "source": "test", "method": "GET", "expected": "x", "observed": "y"},
        ]
        result = engine._group_signals(signals)
        assert len(result) == 1
        assert result[0]["confidence"] == "HIGH"

    def test_calculate_anomaly_score_basic(self):
        engine = AnomalyEngine()
        signals = [
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ]
        score = engine._calculate_anomaly_score(signals)
        assert 10 <= score <= 100

    def test_calculate_anomaly_score_critical(self):
        engine = AnomalyEngine()
        signals = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]
        score = engine._calculate_anomaly_score(signals)
        assert score > 30

    def test_load_json_list_missing(self, tmp_path: Path):
        engine = AnomalyEngine()
        result = engine._load_json_list(tmp_path / "nonexistent.json")
        assert result == []

    def test_load_json_list_valid(self, tmp_path: Path):
        engine = AnomalyEngine()
        p = tmp_path / "data.json"
        with open(p, "w") as f:
            json.dump([1, 2, 3], f)
        result = engine._load_json_list(p)
        assert result == [1, 2, 3]

    def test_load_json_list_invalid(self, tmp_path: Path):
        engine = AnomalyEngine()
        p = tmp_path / "bad.json"
        with open(p, "w") as f:
            f.write("not json")
        result = engine._load_json_list(p)
        assert result == []

    def test_load_json_dict_missing(self, tmp_path: Path):
        engine = AnomalyEngine()
        result = engine._load_json_dict(tmp_path / "nonexistent.json")
        assert result is None

    def test_load_json_dict_valid(self, tmp_path: Path):
        engine = AnomalyEngine()
        p = tmp_path / "data.json"
        with open(p, "w") as f:
            json.dump({"key": "value"}, f)
        result = engine._load_json_dict(p)
        assert result == {"key": "value"}

    def test_load_json_dict_invalid_json(self, tmp_path: Path):
        engine = AnomalyEngine()
        p = tmp_path / "bad.json"
        with open(p, "w") as f:
            f.write("{invalid json}")
        assert engine._load_json_dict(p) is None

    def test_analyze_with_multiple_sources(self, tmp_path: Path):
        web_dir = tmp_path / "profiles" / "web_intelligence"
        web_dir.mkdir(parents=True, exist_ok=True)
        with open(web_dir / "endpoint_inventory.json", "w") as f:
            json.dump([{"url": "https://example.com/admin", "method": "GET"}], f)
        api_dir = tmp_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "api_inventory.json", "w") as f:
            json.dump({"endpoints": [{"url": "https://example.com/api/users", "method": "GET"}]}, f)
        bounty_dir = tmp_path / "profiles" / "bug_bounty"
        bounty_dir.mkdir(parents=True, exist_ok=True)
        with open(bounty_dir / "headless_routes.json", "w") as f:
            json.dump([{"url": "https://example.com/hidden", "method": "GET"}], f)
        engine = AnomalyEngine()
        result = engine.analyze(tmp_path)
        assert len(result) >= 1

    def test_analyze_with_api_data_list(self, tmp_path: Path):
        api_dir = tmp_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "api_inventory.json", "w") as f:
            json.dump([{"url": "https://example.com/admin", "method": "GET"}], f)
        engine = AnomalyEngine()
        result = engine.analyze(tmp_path)
        assert result == []

    def test_headers_as_string_skipped(self):
        engine = AnomalyEngine()
        endpoints = [{"url": "https://example.com/test", "method": "GET", "_source": "test", "response_headers": "INVALID"}]
        signals = engine._detect_rare_headers(endpoints)
        assert len(signals) == 0
