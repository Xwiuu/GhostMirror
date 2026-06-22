from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ghostmirror.modules.bug_bounty.network_capture import NetworkCapture
from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard


class TestNetworkCapture:
    @pytest.fixture
    def capture(self) -> NetworkCapture:
        return NetworkCapture()

    def test_init(self, capture: NetworkCapture) -> None:
        assert capture._requests == []
        assert capture._responses == []

    def test_ingest_empty(self, capture: NetworkCapture) -> None:
        capture.ingest([])
        assert capture.get_captured() == []

    def test_ingest_single_request(self, capture: NetworkCapture) -> None:
        requests = [{"url": "https://example.com/api/users", "method": "GET", "resource_type": "xhr", "headers": {}}]
        capture.ingest(requests)
        captured = capture.get_captured()
        assert len(captured) == 1
        assert captured[0]["url"] == "https://example.com/api/users"
        assert captured[0]["method"] == "GET"
        assert captured[0]["is_api"] is True

    def test_ingest_with_scope_guard(self, capture: NetworkCapture) -> None:
        scope_guard = MagicMock(spec=BountyScopeGuard)
        scope_guard.enforce_scope.side_effect = Exception("Out of scope")
        requests = [{"url": "https://outofscope.com/api", "method": "GET", "headers": {}}]
        capture.ingest(requests, scope_guard)
        assert capture.get_captured() == []

    def test_ingest_with_sanitization(self, capture: NetworkCapture) -> None:
        scope_guard = MagicMock(spec=BountyScopeGuard)
        scope_guard.enforce_scope.return_value = None
        scope_guard.sanitize_headers.return_value = {"authorization": "Bearer ****5678"}
        requests = [{
            "url": "https://example.com/api/data",
            "method": "POST",
            "headers": {"authorization": "Bearer secret-token-12345678"},
        }]
        capture.ingest(requests, scope_guard)
        captured = capture.get_captured()
        assert captured[0]["headers"]["authorization"] == "Bearer ****5678"
        scope_guard.sanitize_headers.assert_called_once()

    def test_get_api_candidates(self, capture: NetworkCapture) -> None:
        requests = [
            {"url": "https://example.com/page", "method": "GET", "resource_type": "document", "headers": {}},
            {"url": "https://example.com/api/users", "method": "GET", "resource_type": "xhr", "headers": {}},
            {"url": "https://example.com/graphql", "method": "POST", "resource_type": "fetch", "headers": {}},
        ]
        capture.ingest(requests)
        apis = capture.get_api_candidates()
        assert len(apis) == 2

    def test_extract_params(self, capture: NetworkCapture) -> None:
        assert capture._extract_params("https://example.com/page") == []
        assert capture._extract_params("https://example.com/page?q=hello&page=1") == ["q", "page"]
        assert capture._extract_params("https://example.com/page?q=hello#section") == ["q"]

    def test_is_api_candidate(self, capture: NetworkCapture) -> None:
        assert capture._is_api_candidate("https://example.com/api/users") is True
        assert capture._is_api_candidate("https://example.com/graphql") is True
        assert capture._is_api_candidate("https://example.com/rest/v1/users") is True
        assert capture._is_api_candidate("https://example.com/page.html") is False
        assert capture._is_api_candidate("https://example.com/style.css") is False

    def test_ingest_multiple_requests(self, capture: NetworkCapture) -> None:
        requests = [
            {"url": "https://example.com/api/1", "method": "GET", "headers": {}},
            {"url": "https://example.com/api/2", "method": "POST", "headers": {}},
            {"url": "https://example.com/api/3", "method": "PUT", "headers": {}},
        ]
        capture.ingest(requests)
        assert len(capture.get_captured()) == 3

    def test_resource_type_classification(self, capture: NetworkCapture) -> None:
        requests = [
            {"url": "https://example.com/", "method": "GET", "resource_type": "document", "headers": {}},
            {"url": "https://example.com/data", "method": "GET", "resource_type": "xhr", "headers": {}},
            {"url": "wss://example.com/socket", "method": "", "resource_type": "websocket", "headers": {}},
        ]
        capture.ingest(requests)
        types = [r["resource_type"] for r in capture.get_captured()]
        assert "document" in types
        assert "xhr" in types
        assert "websocket" in types
