from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel, WebIndicator
from ghostmirror.models.parameter_profile import ParameterProfile

logger = get_logger()

SSRF_PARAM_PATTERNS: set[str] = {
    "url", "uri", "target", "endpoint",
    "redirect", "redirect_url", "redirect_uri",
    "callback", "callback_url", "callback_uri",
    "webhook", "webhook_url",
    "return", "return_url", "return_to",
    "next", "next_url",
    "path", "filepath",
    "fetch", "fetch_url",
    "proxy", "proxy_url",
    "source", "src",
    "link", "href",
    "image", "img", "image_url",
    "avatar", "avatar_url",
    "icon", "icon_url",
    "css", "style",
    "script", "script_url",
    "import", "include",
    "load", "resource",
    "host", "server",
}

WEBHOOK_PATTERN = {
    "discord": "discord.com/api/webhooks",
    "slack": "hooks.slack.com",
    "teams": "webhook.office.com",
    "github": "api.github.com/hooks",
    "stripe": "hooks.stripe.com",
    "sendgrid": "api.sendgrid.com",
    "datadog": "app.datadoghq.com",
    "sentry": "o*.ingest.sentry.io",
    "pagerduty": "events.pagerduty.com",
}


class SSRFIndicators:
    def analyze(
        self,
        parameters: list[ParameterProfile],
        js_findings: dict[str, Any] | None = None,
    ) -> list[WebIndicator]:
        logger.info("SSRF_INDICATORS_START")
        indicators: list[WebIndicator] = []

        for param in parameters:
            if param.name.lower() in SSRF_PARAM_PATTERNS:
                location = param.locations[0] if param.locations else ""
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.SSRF,
                    title=f"SSRF Parameter: {param.name}",
                    description=f"Parameter '{param.name}' is commonly used for URL fetching and may be vulnerable to SSRF.",
                    endpoint=location,
                    parameter=param.name,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=SeverityLevel.MEDIUM,
                    evidence=f"Parameter '{param.name}' found in {len(param.locations)} locations",
                    owasp_category="A10:2021 – Server-Side Request Forgery",
                    recommendation=f"Review parameter '{param.name}' for SSRF. Implement URL allowlisting and validate scheme/host.",
                ))

        if js_findings:
            webhooks_found = js_findings.get("internal_urls", [])
            for url in webhooks_found:
                for service, pattern in WEBHOOK_PATTERN.items():
                    if pattern.replace("*", "") in url.lower():
                        indicators.append(WebIndicator(
                            indicator_type=IndicatorType.SSRF,
                            title=f"Webhook URL Found: {service}",
                            description=f"A {service} webhook URL was found, which could be used for SSRF callbacks.",
                            confidence=ConfidenceLevel.MEDIUM,
                            severity=SeverityLevel.HIGH,
                            evidence=f"Webhook URL: {url[:200]}",
                            owasp_category="A10:2021 – Server-Side Request Forgery",
                            recommendation=f"Ensure the {service} webhook URL is not exposed and access is restricted.",
                        ))

        logger.info("SSRF_INDICATORS_DONE total={}", len(indicators))
        return indicators
