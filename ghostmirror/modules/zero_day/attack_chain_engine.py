from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class AttackChainEngine:
    def __init__(self) -> None:
        self.chains: list[dict[str, Any]] = []

    def analyze(self, project_path: Path | str) -> list[dict[str, Any]]:
        project_path = Path(project_path)
        logger.info("ATTACK_CHAIN_ENGINE_START project={}", project_path.name)
        self.chains = []

        web_dir = project_path / "profiles" / "web_intelligence"
        api_dir = project_path / "profiles" / "api_security"
        bounty_dir = project_path / "profiles" / "bug_bounty"

        jwt_profile = self._load_json_dict(api_dir / "jwt_profile.json") or {}
        graphql_profile = self._load_json_dict(api_dir / "graphql_profile.json") or {}
        api_inv = self._load_json_dict(api_dir / "api_inventory.json") or {}
        objects = self._load_json_list(api_dir / "object_inventory.json")
        correlations = self._load_json_list(api_dir / "api_correlations.json")
        sourcemaps = self._load_json_list(bounty_dir / "sourcemap_profile.json")
        routes = self._load_json_list(bounty_dir / "headless_routes.json")
        endpoints = self._load_json_list(web_dir / "endpoint_inventory.json")

        self._chain_jwt_admin_object(jwt_profile, api_inv, objects)
        self._chain_graphql_introspection(graphql_profile, api_inv)
        self._chain_sourcemap_internal_routes(sourcemaps, routes, endpoints)
        self._chain_jwt_graphql(jwt_profile, graphql_profile, api_inv)
        self._chain_admin_sensitive_access(endpoints, api_inv, objects)
        self._chain_api_object_relationships(api_inv, objects, correlations)

        self.chains.sort(key=lambda c: c["score"], reverse=True)
        logger.info("ATTACK_CHAIN_ENGINE_DONE chains={}", len(self.chains))
        return self.chains

    def _chain_jwt_admin_object(
        self,
        jwt_profile: dict[str, Any],
        api_inv: dict[str, Any],
        objects: list[dict[str, Any]],
    ) -> None:
        has_jwt = bool(jwt_profile.get("jwt_detected", False) or jwt_profile.get("has_jwt", False))
        admin_endpoints = self._find_admin_endpoints(api_inv)
        sensitive_objects = self._find_sensitive_objects(objects)

        if has_jwt and admin_endpoints and sensitive_objects:
            score = min(len(admin_endpoints) * 10 + len(sensitive_objects) * 10 + 40, 100)
            self.chains.append({
                "title": "JWT + Admin API + Sensitive Object Chain",
                "description": f"JWT authentication, {len(admin_endpoints)} admin endpoint(s), and {len(sensitive_objects)} sensitive object type(s) detected. This combination may indicate authorization control weaknesses.",
                "confidence": "HIGH" if len(admin_endpoints) >= 3 else "MEDIUM",
                "severity": "CRITICAL",
                "score": score,
                "components": ["JWT Authentication", "Admin API Endpoints", "Sensitive Objects"],
                "attack_vector": "Bypass or forge JWT tokens to access admin endpoints and manipulate sensitive objects",
                "potential_impact": "Unauthorized access to sensitive data, privilege escalation, data manipulation",
                "recommendation": "Manual validation required: Test JWT strength, authorization on admin endpoints, and object-level access controls.",
            })

    def _chain_graphql_introspection(
        self,
        graphql_profile: dict[str, Any],
        api_inv: dict[str, Any],
    ) -> None:
        introspection_enabled = graphql_profile.get("introspection_enabled", False) or graphql_profile.get("introspection", {}).get("enabled", False)
        gql_endpoint = graphql_profile.get("endpoint", "") or ""
        admin_objects = self._find_admin_graphql_objects(graphql_profile)

        if introspection_enabled and gql_endpoint:
            score = 60 + (20 if admin_objects else 0)
            self.chains.append({
                "title": "GraphQL Introspection + Admin Objects Chain",
                "description": f"GraphQL introspection enabled at {gql_endpoint}. " + (f"Admin objects detected ({len(admin_objects)}). " if admin_objects else "") + "This combination enables comprehensive API mapping and potential data exfiltration.",
                "confidence": "HIGH",
                "severity": "HIGH" if admin_objects else "MEDIUM",
                "score": score,
                "components": ["GraphQL Endpoint", f"Introspection: {gql_endpoint}"],
                "attack_vector": "Use introspection to dump the full GraphQL schema, identify sensitive queries/mutations, and extract data",
                "potential_impact": "Full API schema exposure, sensitive data exfiltration, potential authorization bypass",
                "recommendation": "Manual validation required: Disable introspection in production, test query depth limits, and review authorization on all GraphQL operations.",
            })

    def _chain_sourcemap_internal_routes(
        self,
        sourcemaps: list[dict[str, Any]],
        routes: list[dict[str, Any]],
        endpoints: list[dict[str, Any]],
    ) -> None:
        exposed_sourcemaps = [sm for sm in sourcemaps if sm.get("exposed", False)]
        internal_routes_found = False

        for sm in sourcemaps:
            if sm.get("endpoints") and len(sm.get("endpoints", [])) > 0:
                internal_routes_found = True
                break

        if exposed_sourcemaps and (internal_routes_found or routes):
            total_routes = sum(len(sm.get("endpoints", [])) for sm in sourcemaps if sm.get("endpoints"))
            score = min(50 + len(exposed_sourcemaps) * 10 + total_routes * 3, 100)
            self.chains.append({
                "title": "Source Maps + Internal Routes Chain",
                "description": f"{len(exposed_sourcemaps)} exposed source map(s) revealing {total_routes} internal route(s). This exposes the application's internal structure.",
                "confidence": "HIGH",
                "severity": "HIGH",
                "score": score,
                "components": ["Exposed Source Maps", "Internal Routes"],
                "attack_vector": "Download source maps to reconstruct application source code and discover hidden/internal API endpoints",
                "potential_impact": "Full application source code disclosure, hidden API discovery, sensitive information leakage",
                "recommendation": "Manual validation required: Remove source maps from production and review what was exposed.",
            })

    def _chain_jwt_graphql(
        self,
        jwt_profile: dict[str, Any],
        graphql_profile: dict[str, Any],
        api_inv: dict[str, Any],
    ) -> None:
        has_jwt = bool(jwt_profile.get("jwt_detected", False) or jwt_profile.get("has_jwt", False))
        has_graphql = bool(graphql_profile.get("detected", False) or graphql_profile.get("endpoint", ""))

        if has_jwt and has_graphql:
            self.chains.append({
                "title": "JWT + GraphQL Chain",
                "description": "JWT authentication combined with GraphQL API. Common issues include JWT-based GraphQL authorization bypass and batching attacks.",
                "confidence": "MEDIUM",
                "severity": "HIGH",
                "score": 60,
                "components": ["JWT Authentication", "GraphQL API"],
                "attack_vector": "Exploit JWT weaknesses to bypass GraphQL authorization or use batching attacks to enumerate data",
                "potential_impact": "Unauthorized data access through GraphQL, potential data enumeration",
                "recommendation": "Manual validation required: Test authorization controls across GraphQL resolvers, test for batching attacks.",
            })

    def _chain_admin_sensitive_access(
        self,
        endpoints: list[dict[str, Any]],
        api_inv: dict[str, Any],
        objects: list[dict[str, Any]],
    ) -> None:
        admin_endpoints = self._find_admin_endpoints(api_inv)
        sensitive_objects = self._find_sensitive_objects(objects)

        if admin_endpoints and sensitive_objects:
            score = min(len(admin_endpoints) * 8 + len(sensitive_objects) * 8 + 30, 90)
            self.chains.append({
                "title": "Admin Endpoints + Sensitive Objects Chain",
                "description": f"{len(admin_endpoints)} admin endpoint(s) and {len(sensitive_objects)} sensitive object type(s) detected. This may expose administrative functions to unauthorized users.",
                "confidence": "MEDIUM",
                "severity": "HIGH",
                "score": score,
                "components": ["Admin API Endpoints", "Sensitive Objects"],
                "attack_vector": "Access admin endpoints directly or through IDOR to manipulate sensitive objects",
                "potential_impact": "Unauthorized administrative access, data manipulation, privilege escalation",
                "recommendation": "Manual validation required: Test authentication and authorization on all admin endpoints.",
            })

    def _chain_api_object_relationships(
        self,
        api_inv: dict[str, Any],
        objects: list[dict[str, Any]],
        correlations: list[dict[str, Any]],
    ) -> None:
        if correlations:
            high_score_corr = [c for c in correlations if c.get("score", 0) >= 60]
            if high_score_corr:
                score = min(len(high_score_corr) * 15, 85)
                self.chains.append({
                    "title": "API Object Relationship Chain",
                    "description": f"{len(high_score_corr)} high-score API correlations detected. These may indicate complex object relationships with authorization weaknesses.",
                    "confidence": "MEDIUM",
                    "severity": "HIGH",
                    "score": score,
                    "components": [f"API Correlation: {c.get('title', '')}" for c in high_score_corr[:5]],
                    "attack_vector": "Exploit object relationship chains to access related resources through IDOR or privilege escalation",
                    "potential_impact": "Unauthorized access to related resources, data traversal, privilege escalation",
                    "recommendation": "Manual validation required: Review object relationship chains for IDOR and authorization gaps.",
                })

    def _find_admin_endpoints(self, api_inv: dict[str, Any]) -> list[str]:
        admin = []
        import re
        endpoints = api_inv.get("endpoints", []) if isinstance(api_inv, dict) else api_inv if isinstance(api_inv, list) else []
        for ep in endpoints:
            url = ep.get("url", "") or ep.get("path", "") or ep.get("endpoint", "")
            if re.search(r"admin|administrator|root|superuser|manage", url, re.IGNORECASE):
                admin.append(url)
        return admin

    def _find_sensitive_objects(self, objects: list[dict[str, Any]]) -> list[str]:
        sensitive_keywords = ["user", "admin", "payment", "order", "account", "wallet", "credit", "invoice"]
        found = []
        for obj in objects:
            name = obj.get("name", "") or obj.get("type", "") or obj.get("object", "") or ""
            if isinstance(name, str):
                for kw in sensitive_keywords:
                    if kw in name.lower():
                        found.append(name)
                        break
        return found

    def _find_admin_graphql_objects(self, graphql_profile: dict[str, Any]) -> list[str]:
        admin_objects = []
        schema = graphql_profile.get("schema", {}) or graphql_profile.get("introspection", {}).get("schema", {})
        if isinstance(schema, dict):
            for obj_type in ["types", "objects", "mutations", "queries"]:
                items = schema.get(obj_type, []) if isinstance(schema, dict) else []
                if isinstance(items, list):
                    for item in items:
                        name = item.get("name", "") if isinstance(item, dict) else ""
                        if "admin" in name.lower() or "Admin" in name:
                            admin_objects.append(name)
        return admin_objects

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
