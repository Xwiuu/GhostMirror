from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.bug_bounty_opportunity import BugBountyOpportunity

logger = get_logger()


class BountyScoring:
    def calculate(
        self,
        routes: list[dict[str, Any]] | None = None,
        apis: list[dict[str, Any]] | None = None,
        js_bundles: list[dict[str, Any]] | None = None,
        sourcemap_findings: list[dict[str, Any]] | None = None,
        secrets: list[dict[str, Any]] | None = None,
        interesting_files: list[dict[str, Any]] | None = None,
        parameters: list[dict[str, Any]] | None = None,
    ) -> tuple[list[BugBountyOpportunity], int, str]:
        opportunities: list[BugBountyOpportunity] = []
        score = 0

        if routes:
            auth_routes = [r for r in routes if any(kw in r.get("url", "").lower() for kw in ["login", "auth", "signin", "register"])]
            if auth_routes:
                score += 10
                opportunities.append(BugBountyOpportunity(
                    title="Authentication Endpoints Discovered",
                    type="auth_endpoint",
                    score=10,
                    severity="HIGH",
                    description=f"Found {len(auth_routes)} authentication-related routes",
                    endpoints_affected=[r.get("url", "") for r in auth_routes[:5]],
                    recommendation="Test for authentication bypass, rate limiting issues, and credential enumeration.",
                ))

            admin_routes = [r for r in routes if any(kw in r.get("url", "").lower() for kw in ["admin", "dashboard"])]
            if admin_routes:
                score += 15
                opportunities.append(BugBountyOpportunity(
                    title="Admin/Dashboard Routes Discovered",
                    type="admin",
                    score=15,
                    severity="HIGH",
                    description=f"Found {len(admin_routes)} admin-level routes",
                    endpoints_affected=[r.get("url", "") for r in admin_routes[:5]],
                    recommendation="Test for privilege escalation and improper access controls on admin routes.",
                ))

            payment_routes = [r for r in routes if any(kw in r.get("url", "").lower() for kw in ["payment", "checkout", "cart", "basket", "invoice", "order", "wallet"])]
            if payment_routes:
                score += 20
                opportunities.append(BugBountyOpportunity(
                    title="Payment/Business Logic Routes Discovered",
                    type="business_logic",
                    score=20,
                    severity="CRITICAL",
                    description=f"Found {len(payment_routes)} payment/order-related routes",
                    endpoints_affected=[r.get("url", "") for r in payment_routes[:5]],
                    recommendation="Test for business logic flaws, price manipulation, and IDOR in payment flows.",
                ))

        if apis:
            score += min(len(apis) * 2, 15)
            graphql_apis = [a for a in apis if "graphql" in a.get("url", "").lower() or a.get("content_type") == "graphql"]
            if graphql_apis:
                score += 10
                opportunities.append(BugBountyOpportunity(
                    title="GraphQL Endpoints Discovered",
                    type="api_endpoint",
                    score=10,
                    severity="HIGH",
                    description=f"Found {len(graphql_apis)} GraphQL endpoints",
                    endpoints_affected=[a.get("url", "") for a in graphql_apis],
                    recommendation="Test GraphQL endpoints for introspection, batching attacks, and authorization issues.",
                ))

            auth_apis = [a for a in apis if a.get("auth_required_indicator")]
            if auth_apis:
                score += 5
                opportunities.append(BugBountyOpportunity(
                    title="Authenticated API Endpoints Detected",
                    type="api_endpoint",
                    score=5,
                    severity="MEDIUM",
                    description=f"Found {len(auth_apis)} API endpoints with auth indicators",
                    endpoints_affected=[a.get("url", "") for a in auth_apis[:5]],
                    recommendation="Test for improper access controls, IDOR, and missing authorization checks.",
                ))

        if sourcemap_findings:
            exposed = [s for s in sourcemap_findings if s.get("exposed")]
            if exposed:
                score += 15
                for sm in exposed:
                    opportunities.append(BugBountyOpportunity(
                        title="Exposed Source Map",
                        type="exposed_sourcemap",
                        score=15,
                        severity="HIGH",
                        description=f"Source map exposed at {sm.get('sourcemap_url', '')} with {len(sm.get('files', []))} files",
                        endpoints_affected=[sm.get("sourcemap_url", "")],
                        recommendation="Remove source maps from production or restrict access.",
                    ))

        if secrets:
            for secret in secrets:
                sev = secret.get("severity", "medium")
                sev_score = {"critical": 25, "high": 15, "medium": 8, "low": 3}.get(sev, 5)
                score += sev_score
                opportunities.append(BugBountyOpportunity(
                    title=f"Potential Exposed Secret: {secret.get('type', 'unknown')}",
                    type="potential_secret",
                    score=sev_score,
                    severity=sev.upper(),
                    description=f"Potential {secret.get('type', 'secret')} found at {secret.get('location', 'unknown')}",
                    endpoints_affected=[secret.get("location", "")],
                    recommendation="Review and rotate the exposed secret immediately.",
                ))

        if interesting_files:
            found_files = [f for f in interesting_files if f.get("found")]
            for ff in found_files:
                path = ff.get("path", "")
                sev_score = 10 if path in ("/.env", "/.git/config", "/backup.zip") else 5
                score += sev_score
                opportunities.append(BugBountyOpportunity(
                    title=f"Sensitive File Exposed: {path}",
                    type="interesting_file",
                    score=sev_score,
                    severity="HIGH" if sev_score >= 10 else "MEDIUM",
                    description=f"File {path} was found accessible at {ff.get('url', '')}",
                    endpoints_affected=[ff.get("url", "")],
                    recommendation="Restrict access to sensitive files and remove from document root.",
                ))

        if parameters:
            sensitive_params = [p for p in parameters if p.get("classification") in ("Sensitive", "Auth", "Payment")]
            if sensitive_params:
                score += min(len(sensitive_params) * 3, 10)
                opportunities.append(BugBountyOpportunity(
                    title="Sensitive Parameters Discovered",
                    type="sensitive_param",
                    score=min(len(sensitive_params) * 3, 10),
                    severity="MEDIUM",
                    description=f"Found {len(sensitive_params)} sensitive parameters: {', '.join(p['parameter'] for p in sensitive_params[:8])}",
                    endpoints_affected=list(set(p.get("url", "") for p in sensitive_params)),
                    recommendation="Review sensitive parameters for injection, IDOR, and information disclosure.",
                ))

        normalized_score = min(max(score, 0), 100)
        if normalized_score <= 20:
            level = "LOW"
        elif normalized_score <= 40:
            level = "MEDIUM"
        elif normalized_score <= 70:
            level = "HIGH"
        else:
            level = "CRITICAL"

        logger.info("BOUNTY_SCORING score={} level={} opportunities={}", normalized_score, level, len(opportunities))
        return opportunities, normalized_score, level
