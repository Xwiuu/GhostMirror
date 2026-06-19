from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.web_indicator import IndicatorType
from ghostmirror.models.web_endpoint import WebEndpoint
from ghostmirror.models.web_intelligence_report import CorrelationResult

logger = get_logger()

CORRELATION_RULES: list[dict[str, Any]] = [
    {
        "name": "Open Redirect via Auth Callback",
        "indicator_type": IndicatorType.OPEN_REDIRECT,
        "tech_hint": "auth",
        "owasp": "A01:2021 – Broken Access Control",
        "score": 75,
        "description": "Auth callback or redirect endpoint with redirect parameter found. Common target for open redirect phishing.",
    },
    {
        "name": "SSRF via URL Fetch Endpoint",
        "indicator_type": IndicatorType.SSRF,
        "tech_hint": "",
        "owasp": "A10:2021 – Server-Side Request Forgery",
        "score": 70,
        "description": "URL fetch parameter detected. Could allow server-side request forgery to internal resources.",
    },
    {
        "name": "LFI via Path Traversal Parameter",
        "indicator_type": IndicatorType.PATH_TRAVERSAL,
        "tech_hint": "php",
        "owasp": "A01:2021 – Broken Access Control",
        "score": 80,
        "description": "File inclusion parameter detected in a PHP application. Potential Local File Inclusion vulnerability.",
    },
    {
        "name": "IDOR via Sequential User IDs",
        "indicator_type": IndicatorType.IDOR,
        "tech_hint": "",
        "owasp": "A01:2021 – Broken Access Control",
        "score": 65,
        "description": "Predictable resource IDs found. Without proper authorization, this could allow access to other users' data.",
    },
    {
        "name": "SSTI in Template Engine",
        "indicator_type": IndicatorType.SSTI,
        "tech_hint": "",
        "owasp": "A03:2021 – Injection",
        "score": 60,
        "description": "Template engine detected. If user input is rendered in templates, Server-Side Template Injection may be possible.",
    },
    {
        "name": "SQL Injection via Dynamic Parameter",
        "indicator_type": IndicatorType.SQL_INJECTION,
        "tech_hint": "",
        "owasp": "A03:2021 – Injection",
        "score": 55,
        "description": "Common SQL injection parameters found. Review for proper input sanitization and parameterized queries.",
    },
    {
        "name": "Business Logic Flaw in Checkout",
        "indicator_type": IndicatorType.BUSINESS_LOGIC,
        "tech_hint": "checkout",
        "owasp": "A01:2021 – Broken Access Control",
        "score": 85,
        "description": "Financial parameters found in checkout flow. Manual review required for price manipulation, coupon abuse, etc.",
    },
    {
        "name": "Exposed Secret in JavaScript",
        "indicator_type": IndicatorType.EXPOSED_SECRET,
        "tech_hint": "",
        "owasp": "A05:2021 – Security Misconfiguration",
        "score": 90,
        "description": "Potential secret or API key found in client-side JavaScript.",
    },
    {
        "name": "Reflected XSS via Parameter",
        "indicator_type": IndicatorType.XSS,
        "tech_hint": "",
        "owasp": "A03:2021 – Injection",
        "score": 60,
        "description": "Parameter value reflected in response body. Potential reflected XSS if not properly encoded.",
    },
    {
        "name": "Debug Endpoint Exposure",
        "indicator_type": IndicatorType.INFO_LEAK,
        "tech_hint": "debug",
        "owasp": "A05:2021 – Security Misconfiguration",
        "score": 45,
        "description": "Debug or info-leak pattern detected. May expose sensitive system information.",
    },
]


class CorrelationEngine:
    def correlate(
        self,
        endpoints: list[WebEndpoint],
        indicators: list[WebIndicator] | None = None,
        tech_profile: dict[str, Any] | None = None,
        js_findings: dict[str, Any] | None = None,
        auth_profile: dict[str, Any] | None = None,
    ) -> list[CorrelationResult]:
        logger.info("CORRELATION_ENGINE_START")
        results: list[CorrelationResult] = []
        matched_names: set[str] = set()

        indicators_by_type: dict[str, list[str]] = {}
        all_indicators = indicators or []
        for ind in all_indicators:
            t = ind.indicator_type.value
            if t not in indicators_by_type:
                indicators_by_type[t] = []
            indicators_by_type[t].append(ind.parameter or ind.endpoint)

        tech_hints: set[str] = set()
        if tech_profile:
            server = (tech_profile.get("webserver") or "").lower()
            framework = (tech_profile.get("backend_framework") or "").lower()
            lang = (tech_profile.get("backend_language") or "").lower()
            tech_hints.update([server, framework, lang])
            for tech in tech_profile.get("technologies", []):
                name = (tech.get("name") or "").lower()
                cat = (tech.get("category") or "").lower()
                tech_hints.update([name, cat])

        has_secrets = bool(js_findings and js_findings.get("secrets_found"))
        has_webhooks = bool(js_findings and js_findings.get("internal_urls"))

        has_admin = bool(auth_profile and auth_profile.get("has_admin"))
        has_auth = bool(auth_profile and auth_profile.get("has_login"))

        endpoint_urls = [ep.url for ep in endpoints]

        for rule in CORRELATION_RULES:
            ind_type = rule["indicator_type"].value
            ind_indicators = indicators_by_type.get(ind_type, [])
            if not ind_indicators:
                continue

            tech_match = True
            if rule["tech_hint"]:
                tech_match = any(rule["tech_hint"] in hint for hint in tech_hints)

            if not tech_match:
                continue

            matched_names.add(rule["name"])

            # Find first matching indicator for the ref
            first_indicator = ind_indicators[0] if ind_indicators else ""
            endpoint_url = next(
                (ep.url for ep in endpoints if first_indicator in ep.url or first_indicator in ep.params),
                endpoint_urls[0] if endpoint_urls else "",
            )

            results.append(CorrelationResult(
                title=rule["name"],
                correlation_type=ind_type,
                score=rule["score"],
                classification=self._classify(rule["score"]),
                endpoint=endpoint_url,
                parameter=first_indicator,
                technology=", ".join(sorted(tech_hints)) if tech_hints else "",
                owasp_category=rule["owasp"],
                description=rule["description"],
                indicator_refs=ind_indicators[:5],
                recommendation=self._generate_recommendation(rule),
            ))

        results.sort(key=lambda r: r.score, reverse=True)
        logger.info("CORRELATION_ENGINE_DONE total={}", len(results))
        return results

    def _classify(self, score: int) -> str:
        if score >= 76:
            return "CRITICAL"
        if score >= 51:
            return "HIGH"
        if score >= 26:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendation(self, rule: dict[str, Any]) -> str:
        score = rule["score"]
        if score >= 76:
            return f"CRITICAL: {rule['description']} Prioritize manual testing immediately."
        if score >= 51:
            return f"HIGH: {rule['description']} Schedule manual review."
        if score >= 26:
            return f"MEDIUM: {rule['description']} Include in test plan."
        return f"LOW: {rule['description']} Monitor."
