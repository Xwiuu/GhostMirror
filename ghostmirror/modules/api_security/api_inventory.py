from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.api_endpoint import APIEndpoint
from ghostmirror.models.api_inventory_profile import APIInventoryProfile

logger = get_logger()


class APIInventory:
    def __init__(self) -> None:
        self._endpoints: list[APIEndpoint] = []

    def consolidate(self, project_path: Path) -> APIInventoryProfile:
        logger.info("API_INVENTORY_START project={}", project_path.name)
        self._endpoints = []
        seen: set[tuple[str, str]] = set()

        sources = [
            ("web_intel", self._load_web_intel_endpoints(project_path)),
            ("bug_bounty", self._load_bug_bounty_apis(project_path)),
            ("js_intel", self._load_js_endpoints(project_path)),
            ("network_capture", self._load_network_endpoints(project_path)),
            ("endpoint_discovery", self._load_endpoint_discovery(project_path)),
        ]

        for source_name, entries in sources:
            for entry in entries:
                method = entry.get("method", "GET")
                path = entry.get("path", entry.get("url", ""))
                key = (method, path)
                if key in seen:
                    continue
                seen.add(key)
                confidence = entry.get("confidence", "medium")
                if source_name == "web_intel" and confidence == "medium":
                    confidence = "medium"
                elif source_name == "bug_bounty" and confidence == "medium":
                    confidence = "medium"
                self._endpoints.append(APIEndpoint(
                    method=method,
                    path=path,
                    content_type=entry.get("content_type", ""),
                    auth_required=entry.get("auth_required", entry.get("auth_required_indicator", False)),
                    source=source_name,
                    confidence=confidence,
                    discovered_by=entry.get("discovered_by", source_name),
                    response_code=entry.get("response_code", 0),
                    host=entry.get("host", ""),
                    params=entry.get("params", []),
                    headers=entry.get("headers", {}),
                ))

        return self._build_profile()

    def _build_profile(self) -> APIInventoryProfile:
        methods: dict[str, int] = {}
        sources: dict[str, int] = {}
        confs: dict[str, int] = {}
        content_types: dict[str, int] = {}
        auth_count = 0

        for ep in self._endpoints:
            methods[ep.method] = methods.get(ep.method, 0) + 1
            sources[ep.source] = sources.get(ep.source, 0) + 1
            confs[ep.confidence] = confs.get(ep.confidence, 0) + 1
            if ep.content_type:
                content_types[ep.content_type] = content_types.get(ep.content_type, 0) + 1
            if ep.auth_required:
                auth_count += 1

        return APIInventoryProfile(
            total_endpoints=len(self._endpoints),
            total_methods=methods,
            total_sources=sources,
            total_confidence=confs,
            auth_required_count=auth_count,
            content_types=content_types,
            endpoints=[ep.model_dump(mode="json") for ep in self._endpoints],
        )

    def _load_web_intel_endpoints(self, project_path: Path) -> list[dict[str, Any]]:
        path = project_path / "profiles" / "web_intelligence" / "endpoint_inventory.json"
        return self._load_json_list(path)

    def _load_bug_bounty_apis(self, project_path: Path) -> list[dict[str, Any]]:
        path = project_path / "profiles" / "bug_bounty" / "api_inventory.json"
        return self._load_json_list(path)

    def _load_js_endpoints(self, project_path: Path) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        js_path = project_path / "profiles" / "web_intelligence" / "js_intelligence.json"
        js_data = self._load_json_dict(js_path)
        if js_data:
            for url in js_data.get("internal_urls", []):
                results.append({"method": "GET", "path": url, "source": "js_intel", "confidence": "medium"})
        return results

    def _load_network_endpoints(self, project_path: Path) -> list[dict[str, Any]]:
        path = project_path / "evidence" / "bug_bounty" / "network_capture.json"
        return self._load_json_list(path)

    def _load_endpoint_discovery(self, project_path: Path) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        path = project_path / "profiles" / "web_intelligence" / "endpoint_inventory.json"
        entries = self._load_json_list(path)
        for entry in entries:
            if entry.get("is_api"):
                results.append(entry)
        return results

    def _load_json_list(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                items = data.get("endpoints", data.get("apis", data.get("items", [])))
                if isinstance(items, list):
                    return items
            return []
        except Exception:
            return []

    def _load_json_dict(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def get_endpoints(self) -> list[APIEndpoint]:
        return self._endpoints
