"""Tests for the URL normalizer utility."""

from __future__ import annotations

import pytest

from ghostmirror.app.url_normalizer import normalize_url, normalize_host


class TestNormalizeURL:
    def test_without_scheme(self):
        assert normalize_url("example.com") == "https://example.com"

    def test_with_https(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_with_http(self):
        assert normalize_url("http://example.com") == "http://example.com"

    def test_with_www_and_scheme(self):
        assert normalize_url("https://www.example.com") == "https://www.example.com"

    def test_with_path(self):
        assert normalize_url("https://example.com/admin") == "https://example.com/admin"

    def test_with_query(self):
        assert normalize_url("https://example.com/page?q=1") == "https://example.com/page?q=1"

    def test_with_port(self):
        assert normalize_url("https://example.com:8080") == "https://example.com:8080"

    def test_trailing_spaces(self):
        assert normalize_url("  https://example.com  ") == "https://example.com"

    def test_localhost(self):
        assert normalize_url("http://localhost:3000") == "http://localhost:3000"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            normalize_url("")

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid"):
            normalize_url("not-a-valid-host")


class TestNormalizeHost:
    def test_domain(self):
        assert normalize_host("example.com") == "example.com"

    def test_url(self):
        assert normalize_host("https://example.com/path") == "example.com"

    def test_with_scheme(self):
        assert normalize_host("http://example.com") == "example.com"

    def test_subdomain(self):
        assert normalize_host("https://www.example.com") == "www.example.com"

    def test_ip(self):
        assert normalize_host("192.168.1.1") == "192.168.1.1"
