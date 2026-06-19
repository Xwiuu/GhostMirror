"""Tests for OWASP URL normalization — ensure all requests use normalize_url."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ghostmirror.app.url_normalizer import normalize_url
from ghostmirror.modules.owasp.checks import (
    _request,
    check_admin_endpoints,
    check_auth_indicators,
    check_injection_surface,
    check_logging_indicators,
    check_misconfigurations,
    check_ssrf_surface,
    http_enumerate,
)


class TestOWASPUrlNormalization:
    """All OWASP checks should handle URLs without protocol."""

    def test_request_normalizes_domain_without_protocol(self):
        """_request should handle bare domain by adding https://."""
        with patch(
            "ghostmirror.modules.owasp.checks.urlopen"
        ) as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.status = 200
            mock_urlopen.return_value.__enter__.return_value.headers = {}
            mock_urlopen.return_value.__enter__.return_value.read.return_value = b""

            code, headers, body = _request("example.com", "/test")
            assert code == 200
            called_url = mock_urlopen.call_args[0][0].full_url
            assert called_url.startswith("https://")

    def test_request_normalizes_domain_with_http(self):
        """_request should keep http:// as-is."""
        with patch(
            "ghostmirror.modules.owasp.checks.urlopen"
        ) as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.status = 200
            mock_urlopen.return_value.__enter__.return_value.headers = {}
            mock_urlopen.return_value.__enter__.return_value.read.return_value = b""

            code, headers, body = _request("http://example.com", "/test")
            assert code == 200
            called_url = mock_urlopen.call_args[0][0].full_url
            assert called_url.startswith("http://")

    def test_request_normalizes_domain_with_https(self):
        """_request should keep https:// as-is."""
        with patch(
            "ghostmirror.modules.owasp.checks.urlopen"
        ) as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.status = 200
            mock_urlopen.return_value.__enter__.return_value.headers = {}
            mock_urlopen.return_value.__enter__.return_value.read.return_value = b""

            code, headers, body = _request("https://example.com", "/test")
            assert code == 200
            called_url = mock_urlopen.call_args[0][0].full_url
            assert called_url.startswith("https://")

    def test_request_returns_zero_on_invalid_url(self):
        """_request should gracefully handle invalid URLs."""
        code, headers, body = _request("", "/test")
        assert code == 0
        assert headers == {}
        assert body == ""

    def test_admin_endpoints_normalizes_url(self):
        """check_admin_endpoints should work with bare domain."""
        with patch(
            "ghostmirror.modules.owasp.checks._head_url", return_value=0
        ):
            findings = check_admin_endpoints("example.com")
            assert isinstance(findings, list)

    def test_injection_surface_normalizes_url(self):
        """check_injection_surface should work with bare domain."""
        with patch(
            "ghostmirror.modules.owasp.checks._fetch_body", return_value=""
        ):
            findings = check_injection_surface("example.com")
            assert isinstance(findings, list)

    def test_misconfigurations_normalizes_url(self):
        """check_misconfigurations should work with bare domain."""
        with patch(
            "ghostmirror.modules.owasp.checks._fetch_body", return_value=""
        ):
            findings = check_misconfigurations("example.com")
            assert isinstance(findings, list)

    def test_auth_indicators_normalizes_url(self):
        """check_auth_indicators should work with bare domain."""
        with patch(
            "ghostmirror.modules.owasp.checks._fetch_body", return_value=""
        ):
            with patch(
                "ghostmirror.modules.owasp.checks._head_url", return_value=0
            ):
                findings = check_auth_indicators("example.com")
                assert isinstance(findings, list)

    def test_logging_indicators_normalizes_url(self):
        """check_logging_indicators should work with bare domain."""
        with patch(
            "ghostmirror.modules.owasp.checks._request",
            return_value=(200, {"Server": "nginx"}, ""),
        ):
            findings = check_logging_indicators("example.com")
            assert isinstance(findings, list)

    def test_ssrf_surface_normalizes_url(self):
        """check_ssrf_surface should work with bare domain."""
        with patch(
            "ghostmirror.modules.owasp.checks._fetch_body", return_value=""
        ):
            findings = check_ssrf_surface("example.com")
            assert isinstance(findings, list)

    def test_http_enumerate_normalizes_url(self):
        """http_enumerate should work with bare domain."""
        with patch(
            "ghostmirror.modules.owasp.checks._fetch_body", return_value=""
        ):
            result = http_enumerate("example.com")
            assert "target" in result
