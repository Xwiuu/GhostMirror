from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.bug_bounty.engine import BugBountyEngine


@pytest.fixture
def mock_project() -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "profiles").mkdir(parents=True, exist_ok=True)
    (tmp / "evidence").mkdir(parents=True, exist_ok=True)
    (tmp / "findings").mkdir(parents=True, exist_ok=True)
    (tmp / "profiles" / "bug_bounty").mkdir(parents=True, exist_ok=True)
    (tmp / "evidence" / "bug_bounty").mkdir(parents=True, exist_ok=True)
    (tmp / "profiles" / "web_intelligence").mkdir(parents=True, exist_ok=True)
    tech_profile = {"target": "https://example.com", "technologies": []}
    with open(tmp / "profiles" / "technology_profile.json", "w") as f:
        json.dump(tech_profile, f)
    return tmp


@pytest.fixture
def engine() -> BugBountyEngine:
    return BugBountyEngine(profile="bounty")


class TestBugBountyEngine:
    def test_init(self, engine: BugBountyEngine) -> None:
        assert engine.profile == "bounty"
        assert engine.headless_crawler is not None
        assert engine.network_capture is not None
        assert engine.js_bundle_analyzer is not None
        assert engine.sourcemap_analyzer is not None
        assert engine.api_discovery is not None
        assert engine.parameter_mining is not None
        assert engine.secrets_discovery is not None
        assert engine.interesting_files is not None
        assert engine.subdomain_discovery is not None
        assert engine.scoring is not None
        assert engine.recommendations is not None
        assert engine.report_builder is not None

    @patch("ghostmirror.modules.bug_bounty.engine.BugBountyEngine._collect_js_urls")
    @patch("ghostmirror.modules.bug_bounty.headless_crawler.HeadlessCrawler.crawl")
    @patch("ghostmirror.modules.bug_bounty.headless_crawler.HeadlessCrawler.get_routes")
    @patch("ghostmirror.modules.bug_bounty.js_bundle_analyzer.JSBundleAnalyzer.analyze")
    @patch("ghostmirror.modules.bug_bounty.sourcemap_analyzer.SourcemapAnalyzer.analyze")
    @patch("ghostmirror.modules.bug_bounty.api_discovery.APIDiscovery.combine")
    @patch("ghostmirror.modules.bug_bounty.parameter_mining.ParameterMining.mine")
    @patch("ghostmirror.modules.bug_bounty.secrets_discovery.SecretsDiscovery.scan")
    @patch("ghostmirror.modules.bug_bounty.interesting_files.InterestingFiles.check")
    @patch("ghostmirror.modules.bug_bounty.subdomain_discovery.SubdomainDiscovery.discover")
    def test_analyze_project_bounty_profile(
        self, mock_discover, mock_check, mock_scan, mock_mine, mock_combine,
        mock_sm_analyze, mock_js_analyze, mock_get_routes, mock_crawl,
        mock_collect_js, engine: BugBountyEngine, mock_project: Path,
    ) -> None:
        mock_crawl.return_value = []
        mock_get_routes.return_value = []
        mock_collect_js.return_value = []
        mock_js_analyze.return_value = []
        mock_sm_analyze.return_value = []
        mock_combine.return_value = []
        mock_mine.return_value = []
        mock_scan.return_value = []
        mock_check.return_value = []
        mock_discover.return_value = []

        result = engine.analyze_project(mock_project, "https://example.com")
        assert result["status"] == "completed"
        assert "report" in result
        assert result["overall_score"] >= 0

    def test_analyze_project_no_target(self, engine: BugBountyEngine, mock_project: Path) -> None:
        tech_profile_path = mock_project / "profiles" / "technology_profile.json"
        with open(tech_profile_path, "w") as f:
            json.dump({"target": "", "technologies": []}, f)
        result = engine.analyze_project(mock_project)
        assert result["status"] == "skipped"
        assert "No target" in result.get("reason", "")

    def test__load_json(self, engine: BugBountyEngine) -> None:
        tmp = Path(tempfile.mkdtemp())
        test_file = tmp / "test.json"
        test_file.write_text('{"key": "value"}')
        result = engine._load_json(test_file)
        assert result == {"key": "value"}

    def test__load_json_not_found(self, engine: BugBountyEngine) -> None:
        tmp = Path(tempfile.mkdtemp())
        result = engine._load_json(tmp / "nonexistent.json")
        assert result is None

    def test__load_json_invalid(self, engine: BugBountyEngine) -> None:
        tmp = Path(tempfile.mkdtemp())
        test_file = tmp / "invalid.json"
        test_file.write_text("not json")
        result = engine._load_json(test_file)
        assert result is None

    def test__load_json_list(self, engine: BugBountyEngine) -> None:
        tmp = Path(tempfile.mkdtemp())
        test_file = tmp / "test.json"
        test_file.write_text('[1, 2, 3]')
        result = engine._load_json_list(test_file)
        assert result == [1, 2, 3]

    def test__load_json_list_not_found(self, engine: BugBountyEngine) -> None:
        tmp = Path(tempfile.mkdtemp())
        result = engine._load_json_list(tmp / "nonexistent.json")
        assert result == []

    def test__load_json_list_not_list(self, engine: BugBountyEngine) -> None:
        tmp = Path(tempfile.mkdtemp())
        test_file = tmp / "test.json"
        test_file.write_text('{"a": 1}')
        result = engine._load_json_list(test_file)
        assert result == []

    def test__save_json(self, engine: BugBountyEngine) -> None:
        tmp = Path(tempfile.mkdtemp())
        test_file = tmp / "output.json"
        data = {"hello": "world"}
        engine._save_json(test_file, data)
        assert test_file.exists()
        with open(test_file) as f:
            assert json.load(f) == data

    def test__save_bounty_findings(self, engine: BugBountyEngine, mock_project: Path) -> None:
        from ghostmirror.models.bug_bounty_report import BugBountyReport
        from ghostmirror.models.discovered_secret import DiscoveredSecret
        report = BugBountyReport(
            target="https://example.com",
            secrets=[DiscoveredSecret(
                type="api_key",
                location="https://example.com/app.js",
                snippet="sk_test_xxxxx",
                redacted_snippet="sk_test_***",
                severity="high",
            )],
        )
        engine._save_bounty_findings(mock_project, report)
        findings_file = mock_project / "findings" / "bug_bounty.json"
        assert findings_file.exists()

    def test__collect_js_urls_from_web_intel(self, engine: BugBountyEngine) -> None:
        tmp = Path(tempfile.mkdtemp())
        web_intel_dir = tmp / "profiles" / "web_intelligence"
        web_intel_dir.mkdir(parents=True, exist_ok=True)
        js_intel = {
            "scripts_analyzed": 3,
            "internal_urls": ["https://example.com/app.js", "https://example.com/vendor.js"],
        }
        with open(web_intel_dir / "js_intelligence.json", "w") as f:
            json.dump(js_intel, f)
        result = engine._collect_js_urls("https://example.com", web_intel_dir)
        assert "https://example.com/app.js" in result
        assert "https://example.com/vendor.js" in result

    def test_analyze_project_with_collect_js_urls_fallback(self, engine: BugBountyEngine, mock_project: Path) -> None:
        web_intel_dir = mock_project / "profiles" / "web_intelligence"
        js_intel = {"scripts_analyzed": 0, "internal_urls": []}
        with open(web_intel_dir / "js_intelligence.json", "w") as f:
            json.dump(js_intel, f)
        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = '<html><script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script></html>'
            mock_get.return_value = mock_resp
            result = engine._collect_js_urls("https://example.com", web_intel_dir)
            assert any("app.js" in url for url in result)
            assert any("lib.js" in url for url in result)
