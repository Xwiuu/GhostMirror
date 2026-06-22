from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
    "x-retry-after",
]

STRONG_HEADERS = [
    "x-ratelimit-remaining",
    "ratelimit-remaining",
    "x-rate-limit-remaining",
]


class RateLimitIntelligence:
    def __init__(self) -> None:
        self.headers_found: list[str] = []
        self.classification: str = "Unknown"

    def analyze(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("RATE_LIMIT_INTELLIGENCE_START")
        self.headers_found = []
        self.classification = "Unknown"

        for ep in endpoints:
            all_headers = {}
            if ep.get("headers"):
                all_headers.update(ep.get("headers", {}))
            if ep.get("response_headers"):
                all_headers.update(ep.get("response_headers", {}))

            for hdr_name in all_headers:
                if hdr_name.lower() in RATE_LIMIT_HEADERS:
                    if hdr_name not in self.headers_found:
                        self.headers_found.append(hdr_name)

        self.classification = self._classify()

        result = {
            "rate_limit_detected": len(self.headers_found) > 0,
            "headers_found": self.headers_found,
            "classification": self.classification,
        }

        logger.info("RATE_LIMIT_INTELLIGENCE_DONE classification={}", self.classification)
        return result

    def _classify(self) -> str:
        if not self.headers_found:
            return "Unknown"
        for strong in STRONG_HEADERS:
            if any(strong == h.lower() for h in self.headers_found):
                return "Strong"
        if any("rate" in h.lower() for h in self.headers_found):
            return "Present"
        return "Weak"
