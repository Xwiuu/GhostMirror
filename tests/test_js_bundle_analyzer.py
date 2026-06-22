from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.bug_bounty.js_bundle_analyzer import JSBundleAnalyzer


class TestJSBundleAnalyzer:
    @pytest.fixture
    def analyzer(self) -> JSBundleAnalyzer:
        return JSBundleAnalyzer()

    def test_init(self, analyzer: JSBundleAnalyzer) -> None:
        assert analyzer._client is None

    def test_analyze_empty(self, analyzer: JSBundleAnalyzer) -> None:
        result = analyzer.analyze([])
        assert result == []

    @patch("httpx.Client")
    def test_analyze_bundle_with_endpoints(self, mock_client: MagicMock, analyzer: JSBundleAnalyzer) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
            const API_URL = "/api/v1/users";
            fetch("/api/v1/products");
            axios.get("/api/v1/orders");
        """
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        profiles = analyzer.analyze(["https://example.com/app.js"])
        assert len(profiles) == 1
        p = profiles[0]
        assert any("api" in e.lower() for e in p.endpoints)
        assert p.url == "https://example.com/app.js"
        assert p.content_hash

    @patch("httpx.Client")
    def test_analyze_bundle_with_secrets(self, mock_client: MagicMock, analyzer: JSBundleAnalyzer) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
            const apiKey = "sk_test_123456789abcdefghi";
            const stripePk = "pk_test_abcdefghijklmnopqrs";
            var token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ";
        """
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        profiles = analyzer.analyze(["https://example.com/app.js"])
        assert len(profiles) == 1
        assert len(profiles[0].secrets) > 0

    @patch("httpx.Client")
    def test_analyze_bundle_with_routes(self, mock_client: MagicMock, analyzer: JSBundleAnalyzer) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
            const routes = {
                path: "/dashboard",
                path: "/admin/users",
                path: "/checkout"
            };
            router.navigate("/profile");
        """
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        profiles = analyzer.analyze(["https://example.com/app.js"])
        assert len(profiles) == 1
        routes = profiles[0].routes
        assert any("dashboard" in r for r in routes)

    @patch("httpx.Client")
    def test_analyze_bundle_with_comments(self, mock_client: MagicMock, analyzer: JSBundleAnalyzer) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
            // TODO: implement auth
            // FIXME: this is insecure
            // HACK: temporary workaround
        """
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        profiles = analyzer.analyze(["https://example.com/app.js"])
        assert len(profiles) == 1
        assert len(profiles[0].comments) >= 2

    @patch("httpx.Client")
    def test_analyze_bundle_with_sourcemap(self, mock_client: MagicMock, analyzer: JSBundleAnalyzer) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
            console.log("hello");
            //# sourceMappingURL=app.js.map
        """
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        profiles = analyzer.analyze(["https://example.com/app.js"])
        assert len(profiles) == 1
        assert profiles[0].source_map_present is True
        assert profiles[0].source_map_url == "https://example.com/app.js.map"

    @patch("httpx.Client")
    def test_analyze_bundle_http_error(self, mock_client: MagicMock, analyzer: JSBundleAnalyzer) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        profiles = analyzer.analyze(["https://example.com/missing.js"])
        assert len(profiles) == 0

    @patch("httpx.Client")
    def test_analyze_bundle_feature_flags(self, mock_client: MagicMock, analyzer: JSBundleAnalyzer) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = """
            const feature_flags = { enabled: true, beta: true };
            // admin dashboard
            // payment checkout
        """
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        profiles = analyzer.analyze(["https://example.com/app.js"])
        assert len(profiles) == 1
        assert "admin" in profiles[0].feature_flags or "payment" in profiles[0].feature_flags

    def test_get_all_endpoints(self, analyzer: JSBundleAnalyzer) -> None:
        from ghostmirror.models.js_bundle_profile import JSBundleProfile
        p1 = JSBundleProfile(url="a.js", endpoints=["/api/users", "/api/products"])
        p2 = JSBundleProfile(url="b.js", endpoints=["/api/users", "/api/orders"])
        endpoints = analyzer.get_all_endpoints([p1, p2])
        assert "/api/users" in endpoints
        assert "/api/products" in endpoints
        assert "/api/orders" in endpoints

    def test_get_all_routes(self, analyzer: JSBundleAnalyzer) -> None:
        from ghostmirror.models.js_bundle_profile import JSBundleProfile
        p1 = JSBundleProfile(url="a.js", routes=["/dashboard", "/profile"])
        p2 = JSBundleProfile(url="b.js", routes=["/dashboard", "/admin"])
        routes = analyzer.get_all_routes([p1, p2])
        assert "/dashboard" in routes
        assert "/profile" in routes
        assert "/admin" in routes
