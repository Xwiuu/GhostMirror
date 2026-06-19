from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

import httpx

from ghostmirror.core.logger import get_logger

logger = get_logger()

# JS intelligence patterns
API_ENDPOINT_PATTERN = re.compile(r'["\'](/api/[^"\']*)["\']', re.IGNORECASE)
FETCH_PATTERN = re.compile(r'fetch\(["\']([^"\']+)["\']', re.IGNORECASE)
AXIOS_PATTERN = re.compile(r'\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']', re.IGNORECASE)
ROUTER_PATTERN = re.compile(r'(?:router|route)\.(?:get|post|put|delete)\(["\']([^"\']+)["\']', re.IGNORECASE)

SECRET_PATTERN = re.compile(
    r'(?:api[_-]?key|secret|token|password|apikey|bearer|jwt|auth[_-]?token)'
    r'\s*[:=]\s*["\']([^"\']{8,})["\']',
    re.IGNORECASE,
)

INTERNAL_URL_PATTERN = re.compile(
    r'["\'](https?://(?:localhost|127\.0\.0\.1|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)[^"\']*)["\']',
    re.IGNORECASE,
)

COMMENT_PATTERN = re.compile(r'//\s*(TODO|FIXME|HACK|XXX|BUG|WORKAROUND|REVIEW|OPTIMIZE)[:\s]*(.*)', re.IGNORECASE)

INTERNAL_ROUTE_PATTERN = re.compile(
    r'["\'](/(?:dashboard|admin|internal|private|config|debug|health|metrics|swagger|docs|api)[^"\']*)["\']',
    re.IGNORECASE,
)


class JSIntelligence:
    def __init__(self) -> None:
        self._client: httpx.Client | None = None

    def analyze(self, script_urls: list[str], base_url: str | None = None) -> dict[str, Any]:
        logger.info("JS_INTELLIGENCE_START scripts={}", len(script_urls))
        findings: dict[str, Any] = {
            "scripts_analyzed": 0,
            "endpoints_discovered": [],
            "secrets_found": [],
            "internal_urls": [],
            "interesting_comments": [],
            "internal_routes": [],
            "all_findings": [],
        }

        with httpx.Client(timeout=15.0, verify=False) as client:
            self._client = client
            for script_url in script_urls:
                result = self._analyze_script(script_url, base_url)
                findings["scripts_analyzed"] += 1
                findings["endpoints_discovered"].extend(result.get("endpoints", []))
                findings["secrets_found"].extend(result.get("secrets", []))
                findings["internal_urls"].extend(result.get("internal_urls", []))
                findings["interesting_comments"].extend(result.get("comments", []))
                findings["internal_routes"].extend(result.get("routes", []))

        # Deduplicate
        findings["endpoints_discovered"] = list(set(findings["endpoints_discovered"]))
        findings["internal_routes"] = list(set(findings["internal_routes"]))
        findings["internal_urls"] = list(set(findings["internal_urls"]))

        findings["all_findings"] = (
            [{"type": "endpoint", "value": e} for e in findings["endpoints_discovered"]]
            + [{"type": "secret", "value": s} for s in findings["secrets_found"]]
            + [{"type": "internal_url", "value": u} for u in findings["internal_urls"]]
            + [{"type": "comment", "value": c} for c in findings["interesting_comments"]]
            + [{"type": "route", "value": r} for r in findings["internal_routes"]]
        )

        logger.info(
            "JS_INTELLIGENCE_DONE endpoints={} secrets={} comments={}",
            len(findings["endpoints_discovered"]),
            len(findings["secrets_found"]),
            len(findings["interesting_comments"]),
        )
        return findings

    def _analyze_script(self, script_url: str, base_url: str | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "endpoints": [],
            "secrets": [],
            "internal_urls": [],
            "comments": [],
            "routes": [],
        }

        if not self._client:
            return result

        try:
            resp = self._client.get(script_url, headers={"User-Agent": "GhostMirror/1.0"})
            if resp.status_code != 200:
                return result
            content = resp.text
        except Exception as exc:
            logger.debug("JS_INTELLIGENCE_SKIP url={} reason={}", script_url, exc)
            return result

        result["endpoints"] = (
            API_ENDPOINT_PATTERN.findall(content)
            + FETCH_PATTERN.findall(content)
            + AXIOS_PATTERN.findall(content)
        )

        result["secrets"] = [m[0] for m in SECRET_PATTERN.findall(content) if len(m) > 0]
        if isinstance(result.get("secrets"), list):
            pass
        else:
            result["secrets"] = []

        result["internal_urls"] = INTERNAL_URL_PATTERN.findall(content)
        result["routes"] = ROUTER_PATTERN.findall(content) + INTERNAL_ROUTE_PATTERN.findall(content)

        comments = COMMENT_PATTERN.findall(content)
        result["comments"] = [f"{tag}: {text.strip()}" for tag, text in comments]

        return result
