from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard

logger = get_logger()


class NetworkCapture:
    def __init__(self) -> None:
        self._requests: list[dict[str, Any]] = []
        self._responses: list[dict[str, Any]] = []

    def ingest(self, requests: list[dict[str, Any]], scope_guard: BountyScopeGuard | None = None) -> None:
        for req in requests:
            url = req.get("url", "")
            if scope_guard:
                try:
                    scope_guard.enforce_scope(url)
                except Exception:
                    continue

            headers = req.get("headers", {})
            if scope_guard:
                headers = scope_guard.sanitize_headers(headers)

            entry = {
                "url": url,
                "method": req.get("method", "GET"),
                "resource_type": req.get("resource_type", "unknown"),
                "headers": headers,
                "query_params": self._extract_params(url),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "is_api": self._is_api_candidate(url),
            }
            self._requests.append(entry)

    def get_captured(self) -> list[dict[str, Any]]:
        return self._requests

    def get_api_candidates(self) -> list[dict[str, Any]]:
        return [r for r in self._requests if r.get("is_api")]

    def _extract_params(self, url: str) -> list[str]:
        if "?" not in url:
            return []
        query = url.split("?", 1)[1].split("#")[0]
        params = []
        for pair in query.split("&"):
            if "=" in pair:
                params.append(pair.split("=")[0])
        return params

    def _is_api_candidate(self, url: str) -> bool:
        indicators = ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/",
                      ".json", ".xml", "/rpc", "/trpc", "/ajax"]
        lower = url.lower()
        for ind in indicators:
            if ind in lower:
                return True
        return False
