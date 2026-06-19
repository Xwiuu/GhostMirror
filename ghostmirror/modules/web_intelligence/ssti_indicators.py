from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel, WebIndicator
from ghostmirror.models.web_endpoint import WebEndpoint

logger = get_logger()

TEMPLATE_ENGINE_SIGNATURES: dict[str, list[str]] = {
    "Jinja2": ["jinja", "jinja2", "flask", "flask/", "python/3.", "python2.", "python3."],
    "Twig": ["twig", "symfony", "symphony", "_symfony", "php/"],
    "Velocity": ["velocity", "apache-velocity", "java/"],
    "Freemarker": ["freemarker", "free marker", ".ftl"],
    "Handlebars": ["handlebars", "hbs", "express-handlebars", "express"],
    "Mustache": ["mustache", "mustache.java", "mustache.js"],
    "Django": ["django", "wsgi", "python/3.", "mod_wsgi"],
    "Razor": ["razor", "asp.net", "aspnet", ".net", "iis/", "x-aspnet"],
    "Thymeleaf": ["thymeleaf", "spring", "java/", "tomcat"],
    "Smarty": ["smarty", "php/"],
}

TEMPLATE_ERROR_PATTERNS: dict[str, list[str]] = {
    "Jinja2": ["TemplateSyntaxError", "UndefinedError", "jinja2.exceptions"],
    "Twig": ["Twig_Error", "Twig\\Error", "Unable to find template"],
    "Velocity": ["org.apache.velocity", "VelocityException"],
    "Freemarker": ["freemarker.core", "TemplateException", "FreeMarker template error"],
    "Handlebars": ["Handlebars error", "Missing helper"],
}


class SSTIIndicators:
    def analyze(
        self,
        endpoints: list[WebEndpoint],
        tech_profile: dict[str, Any] | None = None,
    ) -> list[WebIndicator]:
        logger.info("SSTI_INDICATORS_START")
        indicators: list[WebIndicator] = []

        detected_engines: set[str] = set()

        if tech_profile:
            technologies = tech_profile.get("technologies", [])
            headers = tech_profile.get("headers", {})
            server = tech_profile.get("webserver", "").lower()
            framework = tech_profile.get("backend_framework", "").lower()
            lang = tech_profile.get("backend_language", "").lower()

            for engine_name, signatures in TEMPLATE_ENGINE_SIGNATURES.items():
                for sig in signatures:
                    if sig in server or sig in framework or sig in lang:
                        detected_engines.add(engine_name)
                        break

            for tech in technologies:
                tech_name = tech.get("name", "").lower()
                for engine_name, signatures in TEMPLATE_ENGINE_SIGNATURES.items():
                    for sig in signatures:
                        if sig in tech_name:
                            detected_engines.add(engine_name)
                            break

        for ep in endpoints:
            html = ep.response_body_sample
            for engine_name, error_patterns in TEMPLATE_ERROR_PATTERNS.items():
                for pattern in error_patterns:
                    if pattern.lower() in html.lower():
                        detected_engines.add(engine_name)
                        indicators.append(WebIndicator(
                            indicator_type=IndicatorType.SSTI,
                            title=f"SSTI Error: {engine_name}",
                            description=f"A {engine_name} template error was detected, suggesting Server-Side Template Injection.",
                            endpoint=ep.url,
                            confidence=ConfidenceLevel.HIGH,
                            severity=SeverityLevel.HIGH,
                            evidence=f"Pattern '{pattern}' matched in response",
                            technology=engine_name,
                            owasp_category="A03:2021 – Injection",
                            recommendation=f"Review user input rendered by {engine_name}. Implement context-aware output encoding.",
                        ))

        for engine in detected_engines:
            if not any(i.indicator_type == IndicatorType.SSTI and engine in i.technology for i in indicators):
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.SSTI,
                    title=f"Template Engine Fingerprinted: {engine}",
                    description=f"The application appears to use {engine}, which may be vulnerable to SSTI if user input is rendered unsafely.",
                    confidence=ConfidenceLevel.LOW,
                    severity=SeverityLevel.INFO,
                    technology=engine,
                    owasp_category="A03:2021 – Injection",
                    recommendation=f"Verify that user input is never passed unsanitized to {engine} templates.",
                ))

        logger.info("SSTI_INDICATORS_DONE total={}", len(indicators))
        return indicators
