from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

SENSITIVE_FIELDS = [
    "role", "roles", "is_admin", "is_admin",
    "permissions", "permission", "user_role",
    "admin", "superuser", "is_superuser",
    "is_active", "is_verified", "is_approved",
    "account_type", "tier", "plan",
    "quota", "limit", "rate_limit",
    "balance", "credit", "wallet_balance",
    "access_level", "clearance",
    "email_verified", "phone_verified",
    "mfa_enabled", "2fa_enabled",
]

COMPLEX_OBJECT_PATTERNS = [
    "user", "profile", "account", "customer",
    "order", "product", "settings",
]


class MassAssignmentIndicators:
    def __init__(self) -> None:
        self.indicators: list[dict[str, Any]] = []

    def analyze(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        logger.info("MASS_ASSIGNMENT_INDICATORS_START")
        self.indicators = []

        for ep in endpoints:
            method = ep.get("method", "GET")
            path = ep.get("path", ep.get("url", ""))

            if method not in ("POST", "PUT", "PATCH"):
                continue

            if not self._has_complex_object(path):
                continue

            confidence = self._calculate_confidence(method, path, ep)
            fields = [f for f in SENSITIVE_FIELDS if f in path.lower()]

            self.indicators.append({
                "endpoint": path,
                "method": method,
                "confidence": confidence,
                "type": "MASS_ASSIGNMENT",
                "sensitive_fields_hint": fields,
                "description": f"Potential Mass Assignment at {method} {path}",
            })

        logger.info("MASS_ASSIGNMENT_INDICATORS_DONE indicators={}", len(self.indicators))
        return self.indicators

    def _has_complex_object(self, path: str) -> bool:
        lower = path.lower()
        for pattern in COMPLEX_OBJECT_PATTERNS:
            if f"/{pattern}" in lower or f"/{pattern}s" in lower:
                return True
        return False

    def _calculate_confidence(self, method: str, path: str, ep: dict[str, Any]) -> str:
        score = 0
        if method == "PUT":
            score += 2
        elif method == "PATCH":
            score += 3

        for field in SENSITIVE_FIELDS:
            if field in path.lower():
                score += 2

        if "admin" in path.lower() or "config" in path.lower() or "setting" in path.lower():
            score += 2

        if score >= 5:
            return "HIGH"
        if score >= 3:
            return "MEDIUM"
        return "LOW"
