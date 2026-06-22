from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.zero_day.hidden_functionality import HiddenFunctionalityEngine


class TestHiddenFunctionalityEngine:
    def test_init(self):
        engine = HiddenFunctionalityEngine()
        assert engine.hypotheses == []

    def test_analyze_no_data(self, tmp_path: Path):
        engine = HiddenFunctionalityEngine()
        result = engine.analyze(tmp_path)
        assert result == []

    def test_scan_feature_flags_found(self):
        engine = HiddenFunctionalityEngine()
        js_intel = {"scripts_analyzed": [{"content": "const isAdminOverride = true; const debugMode = false;"}]}
        signals = engine._scan_feature_flags(js_intel, [])
        assert len(signals) >= 1
        assert any("isAdminOverride" in s["observed"] for s in signals)

    def test_scan_feature_flags_no_match(self):
        engine = HiddenFunctionalityEngine()
        js_intel = {"scripts_analyzed": [{"content": "const x = 1; function hello() {}"}]}
        signals = engine._scan_feature_flags(js_intel, [])
        assert len(signals) == 0

    def test_scan_feature_flags_from_bundle(self):
        engine = HiddenFunctionalityEngine()
        signals = engine._scan_feature_flags({}, [{"content": "experimental: true, betaFeature: 'enabled'"}])
        assert len(signals) == 2

    def test_scan_debug_routes_admin(self):
        engine = HiddenFunctionalityEngine()
        signals = engine._scan_debug_routes(
            [{"url": "https://example.com/admin"}],
            [],
            [],
        )
        assert len(signals) >= 1
        assert signals[0]["signal_type"] == "debug_route"

    def test_scan_debug_routes_actuator(self):
        engine = HiddenFunctionalityEngine()
        signals = engine._scan_debug_routes(
            [],
            [{"url": "https://example.com/actuator"}],
            [],
        )
        assert len(signals) >= 1

    def test_scan_debug_routes_internal_api(self):
        engine = HiddenFunctionalityEngine()
        signals = engine._scan_debug_routes(
            [],
            [],
            [{"url": "https://example.com/api/internal"}],
        )
        assert len(signals) >= 1
        assert any("internal" in s["observed"] for s in signals)

    def test_scan_internal_functions_found(self):
        engine = HiddenFunctionalityEngine()
        js_intel = {"scripts_analyzed": [{"content": "function _privateHelper() {} function getInternalData() {}"}]}
        signals = engine._scan_internal_functions(js_intel, [])
        assert len(signals) >= 2

    def test_scan_internal_functions_no_match(self):
        engine = HiddenFunctionalityEngine()
        js_intel = {"scripts_analyzed": [{"content": "function publicHelper() {}"}]}
        signals = engine._scan_internal_functions(js_intel, [])
        assert len(signals) == 0

    def test_analyze_sourcemaps_exposed(self):
        engine = HiddenFunctionalityEngine()
        signals = engine._analyze_sourcemaps([
            {"sourcemap_url": "https://example.com/app.js.map", "exposed": True, "files": [], "endpoints": [], "comments": []},
        ])
        assert any(s["signal_type"] == "sourcemap_exposed" for s in signals)

    def test_analyze_sourcemaps_with_routes(self):
        engine = HiddenFunctionalityEngine()
        signals = engine._analyze_sourcemaps([
            {"sourcemap_url": "https://example.com/app.js.map", "exposed": False, "files": ["src/admin.ts"], "endpoints": ["/api/admin/users", "/api/internal/config"], "comments": []},
        ])
        assert any(s["signal_type"] == "sourcemap_routes" for s in signals)

    def test_analyze_sourcemaps_with_sensitive_comments(self):
        engine = HiddenFunctionalityEngine()
        signals = engine._analyze_sourcemaps([
            {"sourcemap_url": "https://example.com/app.js.map", "exposed": False, "files": [], "endpoints": [], "comments": ["TODO: fix this admin bypass"]},
        ])
        assert any(s["signal_type"] == "sourcemap_comment" for s in signals)

    def test_analyze_sourcemaps_empty(self):
        engine = HiddenFunctionalityEngine()
        signals = engine._analyze_sourcemaps([])
        assert len(signals) == 0

    def test_build_hypotheses_feature_flags(self):
        engine = HiddenFunctionalityEngine()
        signals = [
            {"signal_type": "feature_flag", "source": "test", "endpoint": "js", "method": "N/A",
             "expected": "a", "observed": "isAdminOverride", "severity": "MEDIUM", "description": "flag found"},
        ]
        hypotheses = engine._build_hypotheses(signals)
        assert len(hypotheses) >= 1
        assert "Feature Flag" in hypotheses[0]["title"]

    def test_build_hypotheses_debug_routes(self):
        engine = HiddenFunctionalityEngine()
        signals = [
            {"signal_type": "debug_route", "source": "test", "endpoint": "/admin", "method": "GET",
             "expected": "a", "observed": "admin_route", "severity": "MEDIUM", "description": "route found"},
        ]
        hypotheses = engine._build_hypotheses(signals)
        assert len(hypotheses) >= 1
        assert "Hidden" in hypotheses[0]["title"]

    def test_build_hypotheses_sourcemap_exposed(self):
        engine = HiddenFunctionalityEngine()
        signals = [
            {"signal_type": "sourcemap_exposed", "source": "test", "endpoint": "https://example.com/map", "method": "GET",
             "expected": "a", "observed": "exposed", "severity": "HIGH", "description": "map exposed"},
        ]
        hypotheses = engine._build_hypotheses(signals)
        assert len(hypotheses) >= 1
        assert "Source Map" in hypotheses[0]["title"]

    def test_build_hypotheses_empty(self):
        engine = HiddenFunctionalityEngine()
        hypotheses = engine._build_hypotheses([])
        assert hypotheses == []

    def test_extract_text_from_js_intel(self):
        engine = HiddenFunctionalityEngine()
        text = engine._extract_text({"scripts_analyzed": [{"content": "console.log('hello')"}], "content": "var x = 1;"}, [])
        assert "console.log" in text
        assert "var x = 1" in text

    def test_extract_text_with_raw(self):
        engine = HiddenFunctionalityEngine()
        text = engine._extract_text({"raw_content": "raw data here"}, [])
        assert "raw data" in text

    def test_extract_text_from_bundle(self):
        engine = HiddenFunctionalityEngine()
        text = engine._extract_text({}, [{"content": "bundle content", "raw": "raw bundle"}])
        assert "bundle content" in text
        assert "raw bundle" in text

    def test_load_json_list_missing(self, tmp_path: Path):
        engine = HiddenFunctionalityEngine()
        assert engine._load_json_list(tmp_path / "nonexistent.json") == []

    def test_load_json_dict_missing(self, tmp_path: Path):
        engine = HiddenFunctionalityEngine()
        assert engine._load_json_dict(tmp_path / "nonexistent.json") is None

    def test_analyze_with_js_intel(self, tmp_path: Path):
        web_dir = tmp_path / "profiles" / "web_intelligence"
        web_dir.mkdir(parents=True, exist_ok=True)
        with open(web_dir / "js_intelligence.json", "w") as f:
            json.dump({"scripts_analyzed": [{"content": "const isAdminOverride = true"}]}, f)
        engine = HiddenFunctionalityEngine()
        result = engine.analyze(tmp_path)
        assert len(result) >= 1

    def test_analyze_with_bundle_data(self, tmp_path: Path):
        bounty_dir = tmp_path / "profiles" / "bug_bounty"
        bounty_dir.mkdir(parents=True, exist_ok=True)
        with open(bounty_dir / "js_bundle_profile.json", "w") as f:
            json.dump([{"content": "debugMode: true"}], f)
        engine = HiddenFunctionalityEngine()
        result = engine.analyze(tmp_path)
        assert len(result) >= 1

    def test_analyze_with_sourcemaps(self, tmp_path: Path):
        bounty_dir = tmp_path / "profiles" / "bug_bounty"
        bounty_dir.mkdir(parents=True, exist_ok=True)
        with open(bounty_dir / "sourcemap_profile.json", "w") as f:
            json.dump([{"sourcemap_url": "https://example.com/map", "exposed": True, "files": [], "endpoints": ["/admin"], "comments": []}], f)
        engine = HiddenFunctionalityEngine()
        result = engine.analyze(tmp_path)
        assert len(result) >= 1

    def test_analyze_with_endpoints(self, tmp_path: Path):
        web_dir = tmp_path / "profiles" / "web_intelligence"
        web_dir.mkdir(parents=True, exist_ok=True)
        with open(web_dir / "endpoint_inventory.json", "w") as f:
            json.dump([{"url": "https://example.com/actuator/health"}], f)
        engine = HiddenFunctionalityEngine()
        result = engine.analyze(tmp_path)
        assert len(result) >= 1

    def test_extract_text_no_content(self):
        engine = HiddenFunctionalityEngine()
        text = engine._extract_text({}, [])
        assert text == ""

    def test_extract_text_from_list_content(self):
        engine = HiddenFunctionalityEngine()
        text = engine._extract_text({"scripts_analyzed": ["console.log('a')", "console.log('b')"]}, [])
        assert "console.log" in text
