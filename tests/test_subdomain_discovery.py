from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.bug_bounty.subdomain_discovery import SubdomainDiscovery


class TestSubdomainDiscovery:
    @pytest.fixture
    def discovery(self) -> SubdomainDiscovery:
        return SubdomainDiscovery()

    def test_init(self, discovery: SubdomainDiscovery) -> None:
        assert discovery._subdomains == []
        assert discovery._seen == set()

    @patch("httpx.get")
    def test_discover_empty(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("CT logs not available")
        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.return_value = ("example.com", [], ["1.2.3.4"])
            result = discovery.discover("example.com")
        assert result == []

    @patch("httpx.get")
    def test_discover_from_html(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("CT logs not available")
        html = """
            <a href="https://admin.example.com">Admin</a>
            <a href="https://api.example.com">API</a>
            <a href="https://example.com">Main</a>
        """
        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.return_value = ("admin.example.com", [], ["10.0.0.1"])
            result = discovery.discover("example.com", html)
        hostnames = [s.hostname for s in result]
        assert "admin.example.com" in hostnames
        assert "api.example.com" in hostnames

    @patch("httpx.get")
    def test_discover_from_js(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("CT logs not available")
        js_urls = [
            "https://cdn.example.com/app.js",
            "https://api.example.com/data.js",
            "https://example.com/main.js",
        ]
        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.return_value = ("cdn.example.com", [], ["10.0.0.2"])
            result = discovery.discover("example.com", js_urls=js_urls)
        hostnames = [s.hostname for s in result]
        assert "cdn.example.com" in hostnames
        assert "api.example.com" in hostnames

    @patch("httpx.get")
    def test_deduplicates(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("CT logs not available")
        html = """
            <a href="https://admin.example.com">A</a>
            <a href="https://admin.example.com">B</a>
        """
        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.return_value = ("admin.example.com", [], ["10.0.0.1"])
            result = discovery.discover("example.com", html)
        assert len(result) == 1

    @patch("httpx.get")
    def test_extract_from_html_ignores_base_domain(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("CT logs not available")
        html = '<a href="https://example.com">Main</a>'
        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.return_value = ("example.com", [], ["1.2.3.4"])
            result = discovery.discover("example.com", html)
        assert len(result) == 0

    @patch("httpx.get")
    def test_ct_logs(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "admin.example.com\napi.example.com"},
            {"name_value": "mail.example.com"},
        ]
        mock_get.return_value = mock_resp

        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.return_value = ("admin.example.com", [], ["1.2.3.4"])
            result = discovery.discover("example.com")
        hostnames = [s.hostname for s in result]
        assert "admin.example.com" in hostnames
        assert "api.example.com" in hostnames

    @patch("httpx.get")
    def test_ct_logs_http_error(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("Connection error")
        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.return_value = ("example.com", [], ["1.2.3.4"])
            result = discovery.discover("example.com")
        assert result == []

    @patch("httpx.get")
    def test_dns_resolution_failure(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("CT logs not available")
        html = '<a href="https://sub.example.com">Sub</a>'
        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.side_effect = Exception("DNS failure")
            result = discovery.discover("example.com", html)
        assert len(result) == 1
        assert result[0].resolved_ips == []

    @patch("httpx.get")
    def test_get_subdomains(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("CT logs not available")
        with patch("socket.gethostbyname_ex"):
            html = '<a href="https://test.example.com">Test</a>'
            discovery.discover("example.com", html)
            result = discovery.get_subdomains()
            assert len(result) >= 1

    @patch("httpx.get")
    def test_subdomain_profile_fields(self, mock_get: MagicMock, discovery: SubdomainDiscovery) -> None:
        mock_get.side_effect = Exception("CT logs not available")
        with patch("socket.gethostbyname_ex") as mock_dns:
            mock_dns.return_value = ("sub.example.com", [], ["10.0.0.5"])
            html = '<a href="https://sub.example.com">Sub</a>'
            result = discovery.discover("example.com", html)
            assert len(result) == 1
            s = result[0]
            assert s.hostname == "sub.example.com"
            assert s.source == "html_link"
            assert "10.0.0.5" in s.resolved_ips
            assert s.discovered_at
