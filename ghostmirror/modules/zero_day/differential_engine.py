from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class DifferentialEngine:
    def __init__(self) -> None:
        self.signals: list[dict[str, Any]] = []

    def analyze(self, project_path: Path | str) -> list[dict[str, Any]]:
        project_path = Path(project_path)
        logger.info("DIFFERENTIAL_ENGINE_START project={}", project_path.name)
        self.signals = []

        web_intel_dir = project_path / "profiles" / "web_intelligence"
        api_dir = project_path / "profiles" / "api_security"

        endpoints = self._load_endpoints(web_intel_dir, api_dir)
        if not endpoints:
            logger.info("DIFFERENTIAL_ENGINE_SKIPPED no endpoints")
            return []

        groups = self._group_endpoints(endpoints)

        for base_path, variants in groups.items():
            if len(variants) < 2:
                continue
            signals = self._compare_variants(base_path, variants)
            self.signals.extend(signals)

        logger.info("DIFFERENTIAL_ENGINE_DONE signals={}", len(self.signals))
        return self.signals

    def _load_endpoints(self, web_intel_dir: Path, api_dir: Path) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []

        web_endpoints = self._load_json_list(web_intel_dir / "endpoint_inventory.json")
        for ep in web_endpoints:
            ep["_source"] = "web_intelligence"
            endpoints.append(ep)

        api_inv = self._load_json_dict(api_dir / "api_inventory.json") or {}
        api_eps = api_inv.get("endpoints", []) if isinstance(api_inv, dict) else []
        for ep in api_eps:
            ep["_source"] = "api_security"
            endpoints.append(ep)

        return endpoints

    def _group_endpoints(self, endpoints: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = {}

        for ep in endpoints:
            url = ep.get("url", "") or ep.get("path", "") or ep.get("endpoint", "")
            base = self._extract_base_path(url)
            if base:
                if base not in groups:
                    groups[base] = []
                groups[base].append(ep)

        return groups

    def _extract_base_path(self, url: str) -> str | None:
        if not url:
            return None
        url = url.split("?")[0]
        url = url.rstrip("/")
        parts = url.split("/")
        for i in range(len(parts), 0, -1):
            candidate = "/".join(parts[:i])
            if candidate and not candidate.endswith("?") and candidate != url:
                pass
        return url

    def _compare_variants(self, base_path: str, variants: list[dict[str, Any]]) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        statuses = {}
        sizes = {}
        content_types = {}

        for var in variants:
            url = var.get("url", "") or var.get("path", "") or var.get("endpoint", "")
            method = var.get("method", "GET")
            status = var.get("status_code", 0) or var.get("status", 0)
            size = var.get("size", 0) or var.get("content_length", 0) or var.get("response_size", 0)
            ct = var.get("content_type", "") or var.get("mime_type", "") or ""

            key = f"{method}:{url}"

            statuses[key] = status
            sizes[key] = size
            content_types[key] = ct

        if len(set(statuses.values())) > 1:
            signals.append({
                "signal_type": "differential_status",
                "source": "differential_engine",
                "endpoint": base_path,
                "method": "VARIOUS",
                "expected": list(statuses.values())[0],
                "observed": list(statuses.values())[1:] if len(statuses) > 1 else [],
                "severity": "MEDIUM",
                "description": f"Status code varies across endpoint variants of {base_path}: {dict(statuses)}",
            })

        if len(set(sizes.values())) > 1:
            non_zero_sizes = {k: v for k, v in sizes.items() if v > 0}
            if len(set(non_zero_sizes.values())) > 1:
                signals.append({
                    "signal_type": "differential_size",
                    "source": "differential_engine",
                    "endpoint": base_path,
                    "method": "VARIOUS",
                    "expected": list(non_zero_sizes.values())[0] if non_zero_sizes else 0,
                    "observed": list(non_zero_sizes.values())[1:] if len(non_zero_sizes) > 1 else [],
                    "severity": "LOW",
                    "description": f"Response size varies across endpoint variants of {base_path}: {dict(non_zero_sizes)}",
                })

        if len(set(content_types.values())) > 1:
            non_empty_ct = {k: v for k, v in content_types.items() if v}
            if len(set(non_empty_ct.values())) > 1:
                signals.append({
                    "signal_type": "differential_content_type",
                    "source": "differential_engine",
                    "endpoint": base_path,
                    "method": "VARIOUS",
                    "expected": list(non_empty_ct.values())[0] if non_empty_ct else "",
                    "observed": list(non_empty_ct.values())[1:] if len(non_empty_ct) > 1 else [],
                    "severity": "LOW",
                    "description": f"Content-Type varies across endpoint variants of {base_path}: {dict(non_empty_ct)}",
                })

        return signals

    def _load_json_list(self, path: Path) -> list[Any]:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
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
