from __future__ import annotations

import re
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

BFLA_PATTERNS = [
    "/admin", "/internal", "/manage", "/management", "/backoffice",
    "/private", "/staff", "/dashboard", "/panel", "/operator",
    "/superuser", "/adminer", "/administrator",
]

PRIVILEGED_ACTIONS = [
    "delete", "update", "create", "modify", "change", "promote",
    "demote", "deactivate", "activate", "suspend", "ban",
    "grant", "revoke", "assign", "remove",
]


class BFLAIndicators:
    def __init__(self) -> None:
        self.indicators: list[dict[str, Any]] = []

    def analyze(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        logger.info("BFLA_INDICATORS_START")
        self.indicators = []

        for ep in endpoints:
            path = ep.get("path", ep.get("url", ""))
            method = ep.get("method", "GET")
            auth_required = ep.get("auth_required", ep.get("auth_required_indicator", False))

            if self._is_admin_path(path) or self._is_privileged_action(path):
                confidence = self._calculate_confidence(method, auth_required, path)
                self.indicators.append({
                    "endpoint": path,
                    "method": method,
                    "auth_required": auth_required,
                    "confidence": confidence,
                    "type": "BFLA",
                    "description": f"Potential BFLA at {method} {path}",
                })

        logger.info("BFLA_INDICATORS_DONE indicators={}", len(self.indicators))
        return self.indicators

    def _is_admin_path(self, path: str) -> bool:
        lower = path.lower()
        for pattern in BFLA_PATTERNS:
            if pattern in lower:
                return True
        return False

    def _is_privileged_action(self, path: str) -> bool:
        lower = path.lower()
        for action in PRIVILEGED_ACTIONS:
            if action in lower:
                return True
        return False

    def _calculate_confidence(self, method: str, auth_required: bool, path: str) -> str:
        score = 0
        if not auth_required:
            score += 3
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            score += 2
        if any(pattern in path.lower() for pattern in BFLA_PATTERNS):
            score += 2
        if any(action in path.lower() for action in PRIVILEGED_ACTIONS):
            score += 2
        if score >= 6:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW"
