from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel, WebIndicator
from ghostmirror.models.web_endpoint import WebEndpoint

logger = get_logger()

ID_PATTERN = re.compile(r"/(?:user|users|account|profile|order|orders|customer|customers|product|products|item|items|id|document|file|ticket|transaction|payment|invoice|subscription)/(\d+)", re.IGNORECASE)

UUID_PATTERN = re.compile(
    r"/(?:user|users|account|profile|order|orders|id)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)

HASH_ID_PATTERN = re.compile(r"/(?:user|users|account|order|orders|id)/([a-f0-9]{16,})", re.IGNORECASE)


class IDORIndicators:
    def analyze(self, endpoints: list[WebEndpoint]) -> list[WebIndicator]:
        logger.info("IDOR_INDICATORS_START")
        indicators: list[WebIndicator] = []

        for ep in endpoints:
            path = urlparse(ep.url).path

            id_match = ID_PATTERN.search(path)
            if id_match:
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.IDOR,
                    title="Predictable Numeric ID in URL",
                    description=f"A numeric ID '{id_match.group(1)}' was found in the URL path, which may be predictable.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=SeverityLevel.MEDIUM,
                    evidence=f"Pattern: {id_match.group(0)}",
                    owasp_category="A01:2021 – Broken Access Control",
                    recommendation="Use unpredictable IDs (UUIDs) and enforce authorization checks on every request.",
                ))

            uuid_match = UUID_PATTERN.search(path)
            if uuid_match:
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.IDOR,
                    title="UUID in URL Path",
                    description=f"A UUID was found in the URL path. While UUIDs are hard to guess, authorization must still be enforced.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.LOW,
                    severity=SeverityLevel.LOW,
                    evidence=f"UUID: {uuid_match.group(1)}",
                    owasp_category="A01:2021 – Broken Access Control",
                    recommendation="Enforce server-side authorization checks regardless of ID format.",
                ))

            hash_match = HASH_ID_PATTERN.search(path)
            if hash_match:
                indicators.append(WebIndicator(
                    indicator_type=IndicatorType.IDOR,
                    title="Hash ID in URL Path",
                    description=f"A hash ID was found in the URL path. Verify authorization is properly enforced server-side.",
                    endpoint=ep.url,
                    confidence=ConfidenceLevel.LOW,
                    severity=SeverityLevel.LOW,
                    evidence=f"Hash: {hash_match.group(1)[:20]}...",
                    owasp_category="A01:2021 – Broken Access Control",
                    recommendation="Ensure authorization is enforced server-side, not just by hiding IDs.",
                ))

        logger.info("IDOR_INDICATORS_DONE total={}", len(indicators))
        return indicators
