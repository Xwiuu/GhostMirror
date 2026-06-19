from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.web_intelligence.js_intelligence import JSIntelligence


class TestJSIntelligence:
    @pytest.fixture
    def js_intel(self):
        return JSIntelligence()

    def test_analyze_empty_script_list(self, js_intel):
        result = js_intel.analyze([], "https://example.com")
        assert result["scripts_analyzed"] == 0
        assert result["endpoints_discovered"] == []
        assert result["secrets_found"] == []

    @patch("httpx.Client")
    def test_analyze_with_secrets(self, mock_client, js_intel):
        mock_instance = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_instance

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
        const API_KEY = "sk-abc123def456";
        var secret = "my-secret-token-12345";
        let password = "super-secret-password";
        """
        mock_instance.get.return_value = mock_resp

        result = js_intel.analyze(
            ["https://example.com/app.js"],
            "https://example.com",
        )

        assert result["scripts_analyzed"] == 1
        assert len(result["secrets_found"]) > 0

    @patch("httpx.Client")
    def test_analyze_with_api_endpoints(self, mock_client, js_intel):
        mock_instance = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_instance

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
        fetch("/api/users/123");
        axios.get("/api/products");
        const endpoint = "/api/v2/orders";
        """
        mock_instance.get.return_value = mock_resp

        result = js_intel.analyze(
            ["https://example.com/api.js"],
            "https://example.com",
        )

        assert result["scripts_analyzed"] == 1
        assert len(result["endpoints_discovered"]) > 0
        assert any("/api/" in e for e in result["endpoints_discovered"])

    @patch("httpx.Client")
    def test_analyze_with_internal_urls(self, mock_client, js_intel):
        mock_instance = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_instance

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
        var server = "http://localhost:8080";
        var db = "http://10.0.0.5:5432";
        """
        mock_instance.get.return_value = mock_resp

        result = js_intel.analyze(
            ["https://example.com/config.js"],
            "https://example.com",
        )

        assert result["scripts_analyzed"] == 1
        assert len(result["internal_urls"]) > 0

    @patch("httpx.Client")
    def test_analyze_with_comments(self, mock_client, js_intel):
        mock_instance = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_instance

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
        // TODO: fix this later
        // FIXME: security issue here
        // HACK: temporary workaround
        """
        mock_instance.get.return_value = mock_resp

        result = js_intel.analyze(
            ["https://example.com/todo.js"],
            "https://example.com",
        )

        assert result["scripts_analyzed"] == 1
        assert len(result["interesting_comments"]) > 0
        assert any("TODO" in c for c in result["interesting_comments"])

    @patch("httpx.Client")
    def test_analyze_http_error_skipped(self, mock_client, js_intel):
        mock_instance = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_instance

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_instance.get.return_value = mock_resp

        result = js_intel.analyze(
            ["https://example.com/notfound.js"],
            "https://example.com",
        )

        assert result["scripts_analyzed"] == 1

    @patch("httpx.Client")
    def test_dedup_endpoints(self, mock_client, js_intel):
        mock_instance = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_instance

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'fetch("/api/users"); fetch("/api/users");'
        mock_instance.get.return_value = mock_resp

        result = js_intel.analyze(
            ["https://example.com/app.js"],
            "https://example.com",
        )

        assert len(result["endpoints_discovered"]) == 1

    def test_analyze_with_routes(self, js_intel):
        with patch("httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = mock_instance

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = """
            router.get("/admin/users");
            app.post("/api/config");
            """
            mock_instance.get.return_value = mock_resp

            result = js_intel.analyze(
                ["https://example.com/routes.js"],
                "https://example.com",
            )

            assert result["scripts_analyzed"] == 1
