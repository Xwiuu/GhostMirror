from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel, WebIndicator
from ghostmirror.models.parameter_profile import ParameterProfile

logger = get_logger()

TRAVERSAL_PARAMS: set[str] = {
    "file", "file_path", "filepath", "filename",
    "download", "download_path",
    "path", "path_name",
    "template", "template_path", "tpl",
    "include", "require",
    "load", "import",
    "document", "doc",
    "attachment",
    "image", "img",
    "avatar",
    "pdf", "docx",
    "static", "asset",
    "resource", "resources",
    "theme", "layout",
    "view", "page",
    "log", "logfile",
    "config", "conf",
    "backup",
    "sql", "dump",
    "error_log", "access_log",
    "php_path", "wrapper",
}


class TraversalIndicators:
    def analyze(self, parameters: list[ParameterProfile]) -> list[WebIndicator]:
        logger.info("TRAVERSAL_INDICATORS_START")
        indicators: list[WebIndicator] = []

        for param in parameters:
            if param.name.lower() in TRAVERSAL_PARAMS:
                location = param.locations[0] if param.locations else ""
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.PATH_TRAVERSAL,
                    title=f"Path Traversal Parameter: {param.name}",
                    description=f"Parameter '{param.name}' is commonly used for file operations and may be vulnerable to path traversal.",
                    endpoint=location,
                    parameter=param.name,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=SeverityLevel.HIGH,
                    evidence=f"Parameter '{param.name}' found in {len(param.locations)} location(s)",
                    owasp_category="A01:2021 – Broken Access Control",
                    recommendation=f"Review parameter '{param.name}' for path traversal. Validate and sanitize file paths, use a allowlist.",
                ))

        logger.info("TRAVERSAL_INDICATORS_DONE total={}", len(indicators))
        return indicators
