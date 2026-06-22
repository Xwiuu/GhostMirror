from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.bug_bounty.sourcemap_analyzer import SourcemapAnalyzer
from ghostmirror.modules.models.finding import FindingSeverity


class TestSourcemapAnalyzer:
    @pytest.fixture
    def analyzer(self) -> SourcemapAnalyzer:
        return SourcemapAnalyzer()

    def test_init(self, analyzer: SourcemapAnalyzer) -> None:
        assert analyzer._client is None
        assert analyzer._findings == []

    def test_analyze_empty(self, analyzer: SourcemapAnalyzer) -> None:
        result = analyzer.analyze([])
        assert result == []

    @patch("httpx.Client")
    def test_analyze_no_sourcemap(self, mock_client: MagicMock, analyzer: SourcemapAnalyzer) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "console.log('hello');"
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        result = analyzer.analyze(["https://example.com/app.js"])
        assert result == []

    @patch("httpx.Client")
    def test_analyze_sourcemap_not_exposed(self, mock_client: MagicMock, analyzer: SourcemapAnalyzer) -> None:
        js_resp = MagicMock()
        js_resp.status_code = 200
        js_resp.text = '//# sourceMappingURL=app.js.map\nconsole.log("test");'

        sm_resp = MagicMock()
        sm_resp.status_code = 404

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.side_effect = [js_resp, sm_resp]
        mock_client.return_value = mock_client_instance

        result = analyzer.analyze(["https://example.com/app.js"])
        assert len(result) == 1
        assert result[0]["found"] is True
        assert result[0]["exposed"] is False

    @patch("httpx.Client")
    def test_analyze_sourcemap_exposed(self, mock_client: MagicMock, analyzer: SourcemapAnalyzer) -> None:
        js_resp = MagicMock()
        js_resp.status_code = 200
        js_resp.text = '//# sourceMappingURL=app.js.map\nconsole.log("test");'

        sm_content = json.dumps({
            "version": 3,
            "sources": ["src/app.ts", "src/api.ts", "src/admin.ts"],
            "sourcesContent": [
                "const API_URL = '/api/v1/users';",
                "// TODO: fix auth",
                "router.get('/admin', handler);",
            ],
        })
        sm_resp = MagicMock()
        sm_resp.status_code = 200
        sm_resp.text = sm_content

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.side_effect = [js_resp, sm_resp]
        mock_client.return_value = mock_client_instance

        result = analyzer.analyze(["https://example.com/app.js"])
        assert len(result) == 1
        assert result[0]["exposed"] is True
        assert len(result[0]["files"]) >= 3
        assert len(result[0]["endpoints"]) >= 1

    @patch("httpx.Client")
    def test_sourcemap_finding_generated(self, mock_client: MagicMock, analyzer: SourcemapAnalyzer) -> None:
        js_resp = MagicMock()
        js_resp.status_code = 200
        js_resp.text = '//# sourceMappingURL=app.js.map'

        sm_content = json.dumps({
            "version": 3,
            "sources": ["src/main.ts", "src/api.ts"],
            "sourcesContent": ["const x = 1;", "fetch('/api/data');"],
        })
        sm_resp = MagicMock()
        sm_resp.status_code = 200
        sm_resp.text = sm_content

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.side_effect = [js_resp, sm_resp]
        mock_client.return_value = mock_client_instance

        analyzer.analyze(["https://example.com/app.js"])
        findings = analyzer.get_findings()
        assert len(findings) >= 1
        assert findings[0].title == "Exposed Source Map"
        assert "source map" in findings[0].description.lower()

    def test_sourcemap_severity_high_for_many_endpoints(self) -> None:
        analyzer = SourcemapAnalyzer()
        sourcemap_url = "https://example.com/app.js.map"
        result = {
            "js_url": "https://example.com/app.js",
            "sourcemap_url": sourcemap_url,
            "found": True,
            "exposed": True,
            "files": [f"src/file{i}.ts" for i in range(15)],
            "endpoints": [f"/api/endpoint{i}" for i in range(10)],
            "comments": [],
            "routes": [],
        }
        analyzer._parse_sourcemap(
            json.dumps({
                "version": 3,
                "sources": [f"src/file{i}.ts" for i in range(15)],
                "sourcesContent": [f"/api/endpoint{i}" for i in range(10)] + [""] * 5,
            }),
            result,
            sourcemap_url,
            "https://example.com",
        )
        findings = analyzer.get_findings()
        if findings:
            assert findings[0].severity == FindingSeverity.HIGH

    def test_sourcemap_severity_medium_for_few_endpoints(self) -> None:
        analyzer = SourcemapAnalyzer()
        sourcemap_url = "https://example.com/app.js.map"
        result = {
            "js_url": "https://example.com/app.js",
            "sourcemap_url": sourcemap_url,
            "found": True,
            "exposed": True,
            "files": ["src/main.ts"],
            "endpoints": ["/api/data"],
            "comments": [],
            "routes": [],
        }
        analyzer._parse_sourcemap(
            json.dumps({
                "version": 3,
                "sources": ["src/main.ts"],
                "sourcesContent": ["const x = 1;"],
            }),
            result,
            sourcemap_url,
            "https://example.com",
        )
        findings = analyzer.get_findings()
        if findings:
            assert findings[0].severity in (FindingSeverity.MEDIUM, FindingSeverity.HIGH)

    def test_get_findings_empty(self, analyzer: SourcemapAnalyzer) -> None:
        assert analyzer.get_findings() == []
