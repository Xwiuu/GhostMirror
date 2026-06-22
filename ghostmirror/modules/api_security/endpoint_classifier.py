from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

ADMIN_PATTERNS = [
    "/admin", "/administrator", "/backoffice", "/manage", "/management",
    "/internal", "/private", "/staff", "/dashboard", "/panel",
]

API_PATTERNS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
]

AUTH_PATTERNS = [
    "/login", "/signin", "/signup", "/register", "/auth/",
    "/oauth/", "/token", "/authorize", "/logout", "/forgot-password",
    "/reset-password", "/verify", "/mfa", "/2fa",
]

PAYMENT_PATTERNS = [
    "/payment", "/checkout", "/billing", "/invoice", "/charge",
    "/subscription", "/order", "/cart",
]


class EndpointClassifier:
    def classify(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        path = endpoint.get("path", endpoint.get("url", "")).lower()
        result = {
            "is_api": False,
            "is_admin": False,
            "is_auth": False,
            "is_payment": False,
            "is_graphql": False,
        }

        if "/graphql" in path:
            result["is_graphql"] = True
            result["is_api"] = True

        for pattern in API_PATTERNS:
            if pattern in path:
                result["is_api"] = True
                break

        for pattern in ADMIN_PATTERNS:
            if pattern in path:
                result["is_admin"] = True
                break

        for pattern in AUTH_PATTERNS:
            if pattern in path:
                result["is_auth"] = True
                break

        for pattern in PAYMENT_PATTERNS:
            if pattern in path:
                result["is_payment"] = True
                break

        return result

    def classify_batch(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        classified = []
        for ep in endpoints:
            ep["classification"] = self.classify(ep)
            classified.append(ep)
        return classified
