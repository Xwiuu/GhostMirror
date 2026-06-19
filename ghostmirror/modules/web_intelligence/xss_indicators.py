from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel, WebIndicator
from ghostmirror.models.web_endpoint import WebEndpoint
from ghostmirror.models.parameter_profile import ParameterProfile

logger = get_logger()

_HTML_SINKS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"insertAdjacentHTML\s*\(",
    r"\.html\s*\(",
]
HTML_SINK_PATTERN = re.compile(
    "(?:" + "|".join(_HTML_SINKS) + ")",
    re.IGNORECASE,
)

SCRIPT_CONTEXT_PATTERN = re.compile(
    r"(<script[^>]*>.*?</script>|<script[^>]*>)",
    re.IGNORECASE | re.DOTALL,
)

UNSAFE_ATTR_PATTERN = re.compile(
    r"(onclick|onload|onerror|onmouseover|onfocus|onblur|onchange|onsubmit)\s*=",
    re.IGNORECASE,
)

EVAL_PATTERN = re.compile(r"\beval\s*\(|setTimeout\s*\(|setInterval\s*\(|new\s+Function\s*\(", re.IGNORECASE)


class XSSIndicators:
    def analyze(
        self,
        endpoints: list[WebEndpoint],
        parameters: list[ParameterProfile],
    ) -> list[WebIndicator]:
        logger.info("XSS_INDICATORS_START")
        indicators: list[WebIndicator] = []

        for ep in endpoints:
            html = ep.response_body_sample

            if UNSAFE_ATTR_PATTERN.search(html):
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.XSS,
                    title="Unsafe Event Handler Attribute",
                    description="An inline event handler (onclick, onload, etc.) was detected, which may allow XSS.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=SeverityLevel.MEDIUM,
                    evidence=UNSAFE_ATTR_PATTERN.search(html).group(0),
                    owasp_category="A03:2021 – Injection",
                    recommendation="Avoid inline event handlers. Use addEventListener with sanitized input.",
                ))

            if EVAL_PATTERN.search(html):
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.XSS,
                    title="Dangerous JS Function Usage",
                    description="Dynamic code execution (eval, setTimeout with string, etc.) detected.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=SeverityLevel.MEDIUM,
                    evidence=EVAL_PATTERN.search(html).group(0),
                    owasp_category="A03:2021 – Injection",
                    recommendation="Avoid eval(), setTimeout with string arguments, and similar dynamic execution.",
                ))

            if HTML_SINK_PATTERN.search(html):
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.XSS,
                    title="HTML Sink Detected",
                    description="An HTML sink (innerHTML, document.write, etc.) was found, which can lead to DOM-based XSS.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.LOW,
                    severity=SeverityLevel.LOW,
                    evidence=HTML_SINK_PATTERN.search(html).group(0),
                    owasp_category="A03:2021 – Injection",
                    recommendation="Use textContent or innerText instead of innerHTML when inserting user-controlled data.",
                ))

        # Check for parameter reflection (passive XSS detection)
        for ep in endpoints:
            parsed = urlparse(ep.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            html_lower = ep.response_body_sample.lower()
            for param_name, values in qs.items():
                for val in values:
                    if val and val in html_lower:
                        context = "unknown"
                        if re.search(rf'<input[^>]*name=["\']{re.escape(param_name)}["\'][^>]*value=["\']{re.escape(val)}["\']', ep.response_body_sample, re.IGNORECASE):
                            context = "input_value"
                        elif re.search(rf'(?<!["\']){re.escape(val)}(?!["\'])', html_lower):
                            context = "body_text"

                        indicators.append(WebIndicator(
                            indicator_type=IndicatorType.XSS,
                            title=f"Parameter Reflection: {param_name}",
                            description=f"Parameter '{param_name}' with value '{val}' was reflected in the response (context: {context}).",
                            endpoint=ep.url,
                            parameter=param_name,
                            confidence=ConfidenceLevel.MEDIUM if context != "unknown" else ConfidenceLevel.LOW,
                            severity=SeverityLevel.MEDIUM if context == "input_value" else SeverityLevel.LOW,
                            evidence=f"Reflection of '{param_name}={val}' in response body",
                            owasp_category="A03:2021 – Injection",
                            recommendation=f"Review parameter '{param_name}' for XSS. Apply context-aware encoding.",
                        ))

        logger.info("XSS_INDICATORS_DONE total={}", len(indicators))
        return indicators
