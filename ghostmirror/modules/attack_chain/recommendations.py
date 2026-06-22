from __future__ import annotations

from typing import Any

from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType


class RecommendationsEngine:
    RECOMMENDATIONS_MAP: dict[SignalType, list[str]] = {
        SignalType.JWT_DETECTED: [
            "Ensure JWT uses strong signing algorithm (RS256) not 'none' algorithm",
            "Validate JWT signature on every request",
            "Implement short token expiration and refresh token rotation",
        ],
        SignalType.EXPOSED_ADMIN: [
            "Restrict admin endpoints to internal network or VPN only",
            "Implement strong multi-factor authentication for admin access",
            "Review admin endpoint access logs for unauthorized attempts",
        ],
        SignalType.EXPOSED_API: [
            "Implement proper authentication and authorization for all API endpoints",
            "Use API gateway with rate limiting and access controls",
            "Review API documentation exposure and restrict if internal",
        ],
        SignalType.SENSITIVE_OBJECT: [
            "Review object-level access controls",
            "Implement data classification and minimize exposure of sensitive fields",
        ],
        SignalType.BOLA_INDICATOR: [
            "Implement proper authorization checks for object-level access",
            "Use indirect object references or UUIDs instead of sequential IDs",
        ],
        SignalType.BFLA_INDICATOR: [
            "Review function-level authorization for all administrative actions",
            "Implement role-based access control (RBAC) for all functions",
        ],
        SignalType.MASS_ASSIGNMENT_INDICATOR: [
            "Use DTOs (Data Transfer Objects) instead of binding directly to models",
            "Implement allow-lists for mass-assignable fields",
        ],
        SignalType.CVE_KNOWN_EXPLOITED: [
            "Patch affected software immediately",
            "Implement virtual patching via WAF if immediate patching is not possible",
        ],
        SignalType.PUBLIC_EXPLOIT_AVAILABLE: [
            "Prioritize patching based on exploit availability and asset criticality",
            "Monitor for active exploitation attempts in logs",
        ],
        SignalType.MISSING_HEADER: [
            "Implement security headers: Content-Security-Policy, X-Frame-Options, etc.",
            "Use HSTS for all HTTPS responses",
        ],
        SignalType.SOURCE_MAP_EXPOSED: [
            "Disable source map generation in production builds",
            "Configure web server to block .map file access",
        ],
        SignalType.SECRET_EXPOSED: [
            "Rotate exposed credentials immediately",
            "Implement secret scanning in CI/CD pipeline",
            "Use vault solutions for secret management",
        ],
        SignalType.BUSINESS_LOGIC_SURFACE: [
            "Review business logic flows for abuse potential",
            "Implement transaction limits and anomaly detection",
        ],
        SignalType.ZERO_DAY_HYPOTHESIS: [
            "Research the hypothesis through code review and safe testing",
            "Implement additional logging around the suspected functionality",
            "Consider reaching out to vendor if software is third-party",
        ],
        SignalType.GRAPHQL_SURFACE: [
            "Disable GraphQL introspection in production",
            "Implement query depth limiting and rate limiting",
            "Review GraphQL authorization for all resolvers",
        ],
        SignalType.RATE_LIMIT_UNKNOWN: [
            "Implement rate limiting on authentication endpoints",
            "Use account lockout after multiple failed attempts",
        ],
        SignalType.AUTH_SURFACE: [
            "Review authentication implementation for common weaknesses",
            "Implement multi-factor authentication",
            "Ensure password policies meet industry standards",
        ],
    }

    def generate(
        self, signals: list[AttackChainSignal], chain: AttackChainPath,
    ) -> list[str]:
        recommendations: list[str] = []
        seen: set[str] = set()
        for s in signals:
            for rec in self.RECOMMENDATIONS_MAP.get(s.signal_type, []):
                if rec not in seen:
                    recommendations.append(rec)
                    seen.add(rec)
        return recommendations
