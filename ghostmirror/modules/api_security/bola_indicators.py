from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

BOLA_SENSITIVE_OBJECTS = [
    "user", "account", "invoice", "order", "wallet",
    "payment", "transaction", "profile", "balance",
    "customer", "document", "file",
]


class BOLAIndicators:
    def __init__(self) -> None:
        self.indicators: list[dict[str, Any]] = []

    def analyze(self, endpoints: list[dict[str, Any]],
                object_inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
        logger.info("BOLA_INDICATORS_START")
        self.indicators = []

        for ep in endpoints:
            path = ep.get("path", ep.get("url", ""))
            method = ep.get("method", "GET")
            auth_required = ep.get("auth_required", ep.get("auth_required_indicator", False))

            for obj in BOLA_SENSITIVE_OBJECTS:
                if self._path_contains_object(path, obj) and self._has_id_reference(path):
                    confidence = self._calculate_confidence(method, auth_required, path, obj)
                    self.indicators.append({
                        "endpoint": path,
                        "method": method,
                        "object": obj,
                        "auth_required": auth_required,
                        "confidence": confidence,
                        "type": "BOLA",
                        "description": f"Potential BOLA on {obj} object at {method} {path}",
                    })

        logger.info("BOLA_INDICATORS_DONE indicators={}", len(self.indicators))
        return self.indicators

    def _path_contains_object(self, path: str, obj: str) -> bool:
        return f"/{obj}" in path.lower() or f"/{obj}s" in path.lower()

    def _has_id_reference(self, path: str) -> bool:
        import re
        segments = path.split("/")
        for seg in segments:
            if seg.startswith("{") and seg.endswith("}"):
                return True
            if re.match(r"^\d+$", seg):
                return True
            if re.match(r"^[a-fA-F0-9\-]{36}$", seg):
                return True
        return "?id=" in path or "&id=" in path

    def _calculate_confidence(self, method: str, auth_required: bool, path: str, obj: str) -> str:
        score = 0
        if not auth_required:
            score += 3
        if method in ("GET", "DELETE"):
            score += 2
        if method in ("PUT", "PATCH"):
            score += 1
        if self._has_id_reference(path):
            score += 2
        if obj in ("account", "wallet", "invoice", "payment"):
            score += 1
        if "admin" in path.lower() or "internal" in path.lower():
            score += 1
        if score >= 6:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW"
