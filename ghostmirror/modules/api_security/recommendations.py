from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class APIRecommendations:
    def generate(self, report: dict[str, Any]) -> list[str]:
        logger.info("API_RECOMMENDATIONS_START")
        recs: list[str] = []

        apis = report.get("api_inventory", {})
        swagger = report.get("swagger_profile", {}) or {}
        graphql = report.get("graphql_profile", {}) or {}
        jwt = report.get("jwt_profile", {}) or {}
        oauth = report.get("oauth_profile", {}) or {}
        rate_limit = report.get("rate_limit_profile", {}) or {}
        surface = report.get("attack_surface", {}) or {}
        bolas = report.get("bola_indicators", [])
        bflas = report.get("bfla_indicators", [])
        mass_assign = report.get("mass_assignment_indicators", [])

        total_eps = apis.get("total_endpoints", 0)
        if total_eps > 20:
            recs.append(f"High endpoint count ({total_eps}): review API surface for shadow/inventory endpoints.")

        if swagger.get("detected"):
            recs.append("Swagger/OpenAPI documentation exposed. Restrict access in production.")
            if apis.get("auth_required_count", 0) == 0:
                recs.append("Swagger/OpenAPI detected but no auth is required on any endpoints. Enforce authentication.")

        if graphql.get("detected"):
            recs.append("GraphQL endpoint(s) detected at: " + ", ".join(graphql.get("endpoints", [])))
            if graphql.get("frameworks"):
                recs.append("GraphQL framework(s) detected: " + ", ".join(graphql.get("frameworks", [])))

        if jwt.get("detected"):
            if jwt.get("has_none_alg_indicator"):
                recs.append("CRITICAL: JWT 'none' algorithm detected. This allows arbitrary token forgery.")
            if not jwt.get("has_exp"):
                recs.append("JWT tokens missing expiration (exp claim). Tokens should have a limited lifetime.")
            if jwt.get("weak_algorithms"):
                recs.append("Weak JWT algorithms detected: " + ", ".join(jwt.get("weak_algorithms", [])))

        if oauth.get("detected"):
            recs.append("OAuth/OIDC detected. Providers: " + ", ".join(oauth.get("providers", [])))
            if not oauth.get("has_jwks"):
                recs.append("No JWKS endpoint detected. Verify key rotation and signature validation.")

        rl_class = rate_limit.get("classification", "Unknown")
        if rl_class != "Strong":
            recs.append(f"Rate limiting is '{rl_class}'. Implement/enforce rate limiting to prevent abuse.")

        if bolas:
            high_bola = [b for b in bolas if b.get("confidence") == "HIGH"]
            if high_bola:
                recs.append(f"{len(high_bola)} high-confidence BOLA indicators. Review authorization on object-level endpoints.")

        if bflas:
            high_bfla = [b for b in bflas if b.get("confidence") == "HIGH"]
            if high_bfla:
                recs.append(f"{len(high_bfla)} high-confidence BFLA indicators. Review function-level authorization.")

        if mass_assign:
            high_ma = [m for m in mass_assign if m.get("confidence") == "HIGH"]
            if high_ma:
                recs.append(f"{len(high_ma)} high-confidence Mass Assignment indicators. Use DTOs/input validation.")

        if surface:
            score = surface.get("exposure_score", 0)
            if score >= 70:
                recs.append(f"API Exposure Score is {score}/100 (CRITICAL). Immediate review recommended.")
            elif score >= 50:
                recs.append(f"API Exposure Score is {score}/100 (HIGH). Schedule security review.")

        if not recs:
            recs.append("No significant API security issues detected in the current analysis.")

        logger.info("API_RECOMMENDATIONS_DONE count={}", len(recs))
        return recs
