"""Unit tests for the HeadersScanner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest

from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.base.scanner import OutOfScopeError
from ghostmirror.modules.headers.scanner import HeadersScanner


def test_headers_scanner_all_headers_correct(tmp_path: Path, scope_manager: ScopeManager) -> None:
    # 1. Set up project scope
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = HeadersScanner(tmp_path, "example.com", scope_manager)

    # 2. Define standard secure headers
    mock_headers = httpx.Headers({
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
    })
    
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.reason_phrase = "OK"
    mock_response.headers = mock_headers
    mock_response.url = httpx.URL("https://example.com")

    # Mock the client context manager
    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        result = scanner.run()

    # 3. Verify assertions: No findings
    assert result.status == "completed"
    assert result.statistics["total"] == 0
    assert len(result.findings) == 0


def test_headers_scanner_all_headers_missing(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = HeadersScanner(tmp_path, "example.com", scope_manager)

    # Empty headers mock
    mock_headers = httpx.Headers({})
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.reason_phrase = "OK"
    mock_response.headers = mock_headers
    mock_response.url = httpx.URL("https://example.com")

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        result = scanner.run()

    assert result.status == "completed"
    assert result.statistics["total"] == 9
    assert result.statistics["medium"] == 2  # CSP, XFO
    assert result.statistics["low"] == 2     # HSTS, XCTO
    assert result.statistics["info"] == 5    # Referrer, Permissions, CORP, COEP, COOP


def test_headers_scanner_misconfigured_headers(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = HeadersScanner(tmp_path, "example.com", scope_manager)

    # Insecure and misconfigured headers
    mock_headers = httpx.Headers({
        "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
        "Strict-Transport-Security": "max-age=1000",  # too short and missing includeSubDomains
        "X-Frame-Options": "ALLOW-FROM https://evil.com",  # deprecated and weak
        "X-Content-Type-Options": "sniff",  # invalid value
        "Referrer-Policy": "unsafe-url",  # leaks URLs
        "Cross-Origin-Resource-Policy": "invalid-value",
        "Cross-Origin-Embedder-Policy": "invalid-value",
        "Cross-Origin-Opener-Policy": "unsafe-none",
    })
    
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.reason_phrase = "OK"
    mock_response.headers = mock_headers
    mock_response.url = httpx.URL("https://example.com")

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        result = scanner.run()

    assert result.status == "completed"
    # 9 total findings: Permissions-Policy is missing (1), others are misconfigured (8)
    assert result.statistics["total"] == 9
    assert len(result.findings) == 9
    
    # Verify specific misconfigurations were detected
    csp_findings = [f for f in result.findings if "Content-Security-Policy" in f.title]
    assert len(csp_findings) == 1
    assert csp_findings[0].severity == "LOW"  # Misconfigured CSP is Low severity
    
    hsts_findings = [f for f in result.findings if "Strict-Transport-Security" in f.title]
    assert len(hsts_findings) == 1
    assert "less than 1 year" in hsts_findings[0].description


def test_headers_scanner_out_of_scope(tmp_path: Path, scope_manager: ScopeManager) -> None:
    # Scope defined for example.com, target is google.com
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = HeadersScanner(tmp_path, "google.com", scope_manager)

    with pytest.raises(OutOfScopeError):
        scanner.run()


def test_headers_scanner_connection_failure_and_fallback(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = HeadersScanner(tmp_path, "example.com", scope_manager)

    # Mock client class to raise error on HTTPS and succeed on HTTP
    with patch("httpx.Client") as mock_client_class:
        mock_client_https = MagicMock()
        mock_client_https.get.side_effect = httpx.ConnectError("Connection failed")
        
        mock_client_http = MagicMock()
        mock_headers = httpx.Headers({"Content-Security-Policy": "default-src 'self'"})
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.reason_phrase = "OK"
        mock_response.headers = mock_headers
        mock_response.url = httpx.URL("http://example.com")
        mock_client_http.get.return_value = mock_response

        # side_effect allows context managers to return mock_client_https then mock_client_http
        mock_client_class.return_value.__enter__.side_effect = [mock_client_https, mock_client_http]

        result = scanner.run()

    assert result.status == "completed"
    assert result.target == "http://example.com"
