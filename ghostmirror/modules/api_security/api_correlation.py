from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class APICorrelation:
    def __init__(self) -> None:
        self.correlations: list[dict[str, Any]] = []

    def correlate(self, inventory: dict[str, Any],
                  swagger: dict[str, Any],
                  graphql: dict[str, Any],
                  jwt: dict[str, Any],
                  oauth: dict[str, Any],
                  object_inventory: list[dict[str, Any]],
                  bola_indicators: list[dict[str, Any]],
                  bfla_indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
        logger.info("API_CORRELATION_START")
        self.correlations = []

        self._correlate_jwt_admin_api(inventory, jwt, bfla_indicators)
        self._correlate_swagger_sensitive(swagger, object_inventory)
        self._correlate_graphql_auth(graphql, jwt, oauth)
        self._correlate_bola_auth(bola_indicators, inventory)
        self._correlate_mass_assignment_admin(inventory)
        self._correlate_rate_limit_sensitive(inventory)

        logger.info("API_CORRELATION_DONE correlations={}", len(self.correlations))
        return self.correlations

    def _correlate_jwt_admin_api(self, inventory: dict[str, Any],
                                  jwt: dict[str, Any],
                                  bfla: list[dict[str, Any]]) -> None:
        if not jwt.get("detected"):
            return

        admin_eps = [ep for ep in inventory.get("endpoints", [])
                     if ep.get("classification", {}).get("is_admin")]

        if admin_eps and bfla:
            score = 90 if jwt.get("has_none_alg_indicator") or not jwt.get("has_exp") else 75
            self.correlations.append({
                "type": "JWT_ADMIN_API",
                "title": "JWT + Admin API + BFLA Indicators",
                "description": f"JWT auth on {len(admin_eps)} admin endpoint(s) with BFLA risk",
                "score": score,
                "classification": "HIGH" if score >= 75 else "MEDIUM",
                "factors": {
                    "jwt_detected": jwt.get("detected"),
                    "admin_endpoints": len(admin_eps),
                    "bfla_indicators": len(bfla),
                    "jwt_weak": jwt.get("has_none_alg_indicator") or not jwt.get("has_exp"),
                },
            })

    def _correlate_swagger_sensitive(self, swagger: dict[str, Any],
                                      object_inventory: list[dict[str, Any]]) -> None:
        if not swagger.get("detected"):
            return

        sensitive = [o for o in object_inventory if o.get("type") in ("Financial", "Admin", "Security")]
        if sensitive:
            self.correlations.append({
                "type": "SWAGGER_SENSITIVE",
                "title": "Swagger/OpenAPI + Sensitive Objects",
                "description": f"OpenAPI spec available with {len(sensitive)} sensitive objects mapped",
                "score": 70,
                "classification": "HIGH",
                "factors": {
                    "swagger_paths": swagger.get("found_paths", []),
                    "sensitive_objects": len(sensitive),
                },
            })

    def _correlate_graphql_auth(self, graphql: dict[str, Any],
                                 jwt: dict[str, Any],
                                 oauth: dict[str, Any]) -> None:
        if not graphql.get("detected"):
            return

        if not jwt.get("detected") and not oauth.get("detected"):
            self.correlations.append({
                "type": "GRAPHQL_NO_AUTH",
                "title": "GraphQL without Auth Detection",
                "description": "GraphQL endpoint detected but no JWT or OAuth found",
                "score": 60,
                "classification": "MEDIUM",
                "factors": {
                    "graphql_endpoints": graphql.get("endpoints", []),
                },
            })

    def _correlate_bola_auth(self, bola: list[dict[str, Any]],
                              inventory: dict[str, Any]) -> None:
        high_bola = [b for b in bola if b.get("confidence") == "HIGH" and not b.get("auth_required")]
        if high_bola:
            self.correlations.append({
                "type": "BOLA_UNAUTHENTICATED",
                "title": "Unauthenticated BOLA Opportunities",
                "description": f"{len(high_bola)} high-confidence BOLA opportunities without auth",
                "score": 85,
                "classification": "CRITICAL",
                "factors": {
                    "bola_count": len(high_bola),
                },
            })

    def _correlate_mass_assignment_admin(self, inventory: dict[str, Any]) -> None:
        admin_put = [ep for ep in inventory.get("endpoints", [])
                     if ep.get("classification", {}).get("is_admin")
                     and ep.get("method") in ("PUT", "PATCH", "POST")]
        if admin_put:
            self.correlations.append({
                "type": "MASS_ASSIGNMENT_ADMIN",
                "title": "Admin Mass Assignment Surface",
                "description": f"{len(admin_put)} admin endpoints accepting PUT/PATCH/POST",
                "score": 65,
                "classification": "MEDIUM",
                "factors": {
                    "admin_write_endpoints": len(admin_put),
                },
            })

    def _correlate_rate_limit_sensitive(self, inventory: dict[str, Any]) -> None:
        sensitive_unauthed = [ep for ep in inventory.get("endpoints", [])
                              if ep.get("classification", {}).get("is_api")
                              and not ep.get("auth_required")]
        if len(sensitive_unauthed) > 5:
            self.correlations.append({
                "type": "UNRESTRICTED_API_ACCESS",
                "title": "Unrestricted API Access",
                "description": f"{len(sensitive_unauthed)} unauthenticated API endpoints",
                "score": 50,
                "classification": "MEDIUM",
                "factors": {
                    "unauthed_api_count": len(sensitive_unauthed),
                },
            })
