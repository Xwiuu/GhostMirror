from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.discovered_api import DiscoveredAPI

logger = get_logger()


class APIDiscovery:
    def __init__(self) -> None:
        self._apis: list[DiscoveredAPI] = []

    def combine(
        self,
        network_capture_entries: list[dict[str, Any]] | None = None,
        js_endpoints: list[str] | None = None,
        sourcemap_endpoints: list[str] | None = None,
        web_intel_endpoints: list[dict[str, Any]] | None = None,
    ) -> list[DiscoveredAPI]:
        logger.info("API_DISCOVERY_START")
        self._apis = []
        seen: set[str] = set()

        if network_capture_entries:
            for entry in network_capture_entries:
                url = entry.get("url", "")
                if url in seen:
                    continue
                seen.add(url)
                self._apis.append(DiscoveredAPI(
                    method=entry.get("method", "GET"),
                    url=url,
                    path=self._extract_path(url),
                    params=entry.get("query_params", []),
                    content_type="",
                    auth_required_indicator=self._has_auth_hint(entry.get("headers", {})),
                    source="network_capture",
                    confidence="high",
                ))

        if js_endpoints:
            for ep in js_endpoints:
                if ep in seen:
                    continue
                full_url = ep if ep.startswith("http") else ep
                seen.add(ep)
                self._apis.append(DiscoveredAPI(
                    url=full_url,
                    path=self._extract_path(full_url),
                    source="js_bundle",
                    confidence="medium",
                ))

        if sourcemap_endpoints:
            for ep in sourcemap_endpoints:
                if ep in seen:
                    continue
                seen.add(ep)
                self._apis.append(DiscoveredAPI(
                    url=ep,
                    path=self._extract_path(ep),
                    source="sourcemap",
                    confidence="medium",
                ))

        if web_intel_endpoints:
            for entry in web_intel_endpoints:
                url = entry.get("url", "")
                if url in seen:
                    continue
                seen.add(url)
                self._apis.append(DiscoveredAPI(
                    method=entry.get("method", "GET"),
                    url=url,
                    path=self._extract_path(url),
                    source="web_intel",
                    confidence="medium",
                ))

        self._classify_apis()
        logger.info("API_DISCOVERY_DONE total={}", len(self._apis))
        return self._apis

    def _extract_path(self, url: str) -> str:
        from urllib.parse import urlparse
        if "://" in url:
            parsed = urlparse(url)
            return parsed.path or "/"
        return url

    def _has_auth_hint(self, headers: dict) -> bool:
        if not headers:
            return False
        auth_headers = {"authorization", "x-api-key", "x-auth-token", "token", "bearer"}
        for key in headers:
            if key.lower() in auth_headers:
                return True
        return False

    def _classify_apis(self) -> None:
        for api in self._apis:
            lower_url = api.url.lower()
            if "/graphql" in lower_url:
                api.content_type = "graphql"
            elif "/rest" in lower_url:
                api.content_type = "rest"
            elif ".json" in lower_url:
                api.content_type = "json"
