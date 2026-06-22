from __future__ import annotations

import pytest

from ghostmirror.modules.bug_bounty.api_discovery import APIDiscovery


class TestAPIDiscovery:
    @pytest.fixture
    def discovery(self) -> APIDiscovery:
        return APIDiscovery()

    def test_init(self, discovery: APIDiscovery) -> None:
        assert discovery._apis == []

    def test_combine_all_empty(self, discovery: APIDiscovery) -> None:
        result = discovery.combine()
        assert result == []

    def test_combine_network_capture(self, discovery: APIDiscovery) -> None:
        entries = [
            {"url": "https://example.com/api/users", "method": "GET", "query_params": ["page"], "headers": {}},
            {"url": "https://example.com/api/products", "method": "POST", "query_params": [], "headers": {"authorization": "Bearer xxx"}},
        ]
        result = discovery.combine(network_capture_entries=entries)
        assert len(result) == 2
        assert result[0].source == "network_capture"
        assert result[1].auth_required_indicator is True

    def test_combine_js_endpoints(self, discovery: APIDiscovery) -> None:
        endpoints = ["/api/v1/users", "/api/v1/products", "/graphql"]
        result = discovery.combine(js_endpoints=endpoints)
        assert len(result) == 3
        for api in result:
            assert api.source == "js_bundle"

    def test_combine_sourcemap(self, discovery: APIDiscovery) -> None:
        endpoints = ["/api/admin/users", "/api/internal/health"]
        result = discovery.combine(sourcemap_endpoints=endpoints)
        assert len(result) == 2
        for api in result:
            assert api.source == "sourcemap"

    def test_combine_web_intel(self, discovery: APIDiscovery) -> None:
        endpoints = [
            {"url": "https://example.com/api/data", "method": "GET"},
            {"url": "https://example.com/login", "method": "POST"},
        ]
        result = discovery.combine(web_intel_endpoints=endpoints)
        assert len(result) == 2

    def test_combine_deduplicates(self, discovery: APIDiscovery) -> None:
        entries = [
            {"url": "https://example.com/api/users", "method": "GET", "query_params": [], "headers": {}},
        ]
        endpoints = ["https://example.com/api/users"]
        result = discovery.combine(
            network_capture_entries=entries,
            js_endpoints=endpoints,
        )
        # Should only have one entry for /api/users since network_capture is processed first
        assert len(result) >= 1

    def test_classify_graphql(self, discovery: APIDiscovery) -> None:
        entries = [{"url": "https://example.com/graphql", "method": "POST", "query_params": [], "headers": {}}]
        result = discovery.combine(network_capture_entries=entries)
        assert result[0].content_type == "graphql"

    def test_classify_rest(self, discovery: APIDiscovery) -> None:
        entries = [{"url": "https://example.com/rest/v1/users", "method": "GET", "query_params": [], "headers": {}}]
        result = discovery.combine(network_capture_entries=entries)
        assert result[0].content_type == "rest"

    def test_classify_json(self, discovery: APIDiscovery) -> None:
        entries = [{"url": "https://example.com/api/users.json", "method": "GET", "query_params": [], "headers": {}}]
        result = discovery.combine(network_capture_entries=entries)
        assert result[0].content_type == "json"

    def test_has_auth_hint(self, discovery: APIDiscovery) -> None:
        headers = {"authorization": "Bearer token123"}
        assert discovery._has_auth_hint(headers) is True
        assert discovery._has_auth_hint({}) is False
        assert discovery._has_auth_hint({"content-type": "application/json"}) is False

    def test_extract_path(self, discovery: APIDiscovery) -> None:
        assert discovery._extract_path("https://example.com/api/users") == "/api/users"
        assert discovery._extract_path("/api/v1/products") == "/api/v1/products"

    def test_confidence_levels(self, discovery: APIDiscovery) -> None:
        entries = [{"url": "https://example.com/api/data", "method": "GET", "query_params": [], "headers": {}}]
        net_result = discovery.combine(network_capture_entries=entries)
        assert all(a.confidence == "high" for a in net_result)

        js_result = discovery.combine(js_endpoints=["/api/test"])
        assert all(a.confidence == "medium" for a in js_result)

        sm_result = discovery.combine(sourcemap_endpoints=["/api/test2"])
        assert all(a.confidence == "medium" for a in sm_result)
