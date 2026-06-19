from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel, WebIndicator
from ghostmirror.models.parameter_profile import ParameterProfile

logger = get_logger()

REDIRECT_PARAMS: set[str] = {
    "redirect", "redirect_url", "redirect_uri", "redir",
    "url", "uri", "u",
    "next", "next_url", "next_uri",
    "return", "return_url", "return_to", "return_uri",
    "goto", "go_to",
    "destination", "dest", "target",
    "callback", "callback_url",
    "referer", "referrer",
    "out", "external",
    "forward", "forward_url",
    "link", "href",
    "to", "continue",
    "success_url", "failure_url",
    "cancel_url", "error_url",
    "back", "back_url",
    "redirect_to", "redirectUrl", "redirectUri",
}


class RedirectIndicators:
    def analyze(self, parameters: list[ParameterProfile]) -> list[WebIndicator]:
        logger.info("REDIRECT_INDICATORS_START")
        indicators: list[WebIndicator] = []

        for param in parameters:
            if param.name.lower() in REDIRECT_PARAMS:
                location = param.locations[0] if param.locations else ""
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.OPEN_REDIRECT,
                    title=f"Open Redirect Parameter: {param.name}",
                    description=f"Parameter '{param.name}' is commonly used for redirects and may allow open redirect.",
                    endpoint=location,
                    parameter=param.name,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=SeverityLevel.MEDIUM,
                    evidence=f"Parameter '{param.name}' found in {len(param.locations)} location(s)",
                    owasp_category="A01:2021 – Broken Access Control",
                    recommendation=f"Review parameter '{param.name}' for open redirect. Validate URLs against an allowlist.",
                ))

        logger.info("REDIRECT_INDICATORS_DONE total={}", len(indicators))
        return indicators
