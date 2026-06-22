from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.models.finding import FindingModel

logger = get_logger()


class APIFindingsMapper:
    def map_to_findings(self, report: dict[str, Any]) -> list[FindingModel]:
        logger.info("API_FINDINGS_MAPPER_START")
        findings: list[FindingModel] = []
        target = report.get("target", "")

        jwt = report.get("jwt_profile", {}) or {}
        if jwt.get("detected"):
            if jwt.get("has_none_alg_indicator"):
                findings.append(FindingModel(
                    title="JWT 'none' Algorithm Detected",
                    description="JWT tokens with 'none' algorithm indicator found, allowing arbitrary token forgery.",
                    severity="CRITICAL",
                    target=target,
                    module="api_security",
                    evidence=f"Redacted tokens: {jwt.get('redacted_tokens', [])[:2]}",
                    recommendation="Configure JWT library to reject 'none' algorithm. Always validate signature.",
                ))
            if not jwt.get("has_exp"):
                findings.append(FindingModel(
                    title="JWT Missing Expiration Claim",
                    description="JWT tokens without expiration (exp) claim detected.",
                    severity="MEDIUM",
                    target=target,
                    module="api_security",
                    recommendation="Add exp claim with reasonable TTL to all JWT tokens.",
                ))

        bolas = report.get("bola_indicators", [])
        high_bola = [b for b in bolas if b.get("confidence") == "HIGH" and not b.get("auth_required")]
        for bola in high_bola[:5]:
            findings.append(FindingModel(
                title=f"BOLA Opportunity: {bola.get('method', 'GET')} {bola.get('endpoint', '')}",
                description=bola.get("description", "Potential Broken Object Level Authorization"),
                    severity="HIGH",
                    target=target,
                    module="api_security",
                    recommendation="Verify object-level authorization. Ensure users can only access their own objects.",
                ))

        bflas = report.get("bfla_indicators", [])
        high_bfla = [b for b in bflas if b.get("confidence") == "HIGH"]
        for bfla in high_bfla[:5]:
            findings.append(FindingModel(
                title=f"BFLA Opportunity: {bfla.get('method', 'GET')} {bfla.get('endpoint', '')}",
                description=bfla.get("description", "Potential Broken Function Level Authorization"),
                severity="HIGH",
                target=target,
                module="api_security",
                recommendation="Verify function-level authorization. Restrict admin endpoints by role.",
            ))

        mass_assign = report.get("mass_assignment_indicators", [])
        high_ma = [m for m in mass_assign if m.get("confidence") == "HIGH"]
        for ma in high_ma[:5]:
            findings.append(FindingModel(
                title=f"Mass Assignment Surface: {ma.get('method', 'POST')} {ma.get('endpoint', '')}",
                description=ma.get("description", "Potential Mass Assignment vulnerability"),
                    severity="MEDIUM",
                    target=target,
                    module="api_security",
                    recommendation="Use Data Transfer Objects (DTOs) and avoid binding all request fields.",
                ))

        swagger = report.get("swagger_profile", {}) or {}
        if swagger.get("detected"):
            findings.append(FindingModel(
                title="Swagger/OpenAPI Endpoint Exposed",
                description=f"Swagger/OpenAPI documentation available at: {swagger.get('found_paths', [])}",
                severity="INFO",
                target=target,
                module="api_security",
                recommendation="Disable or restrict access to API documentation in production.",
            ))

        graphql = report.get("graphql_profile", {}) or {}
        gql_intel = report.get("graphql_intelligence", {}) or {}
        if graphql.get("detected") and gql_intel.get("has_introspection"):
            findings.append(FindingModel(
                title="GraphQL Introspection Enabled",
                description="GraphQL introspection queries are accepted, exposing the full schema.",
                severity="MEDIUM",
                target=target,
                module="api_security",
                recommendation="Disable introspection in production environments.",
            ))

        logger.info("API_FINDINGS_MAPPER_DONE findings={}", len(findings))
        return findings
