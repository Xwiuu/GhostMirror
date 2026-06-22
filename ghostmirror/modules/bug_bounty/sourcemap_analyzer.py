from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

import httpx

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity

logger = get_logger()

SOURCEMAP_PATTERN = re.compile(r"sourceMappingURL=([^\s'\"]+\.map)")


class SourcemapAnalyzer:
    def __init__(self) -> None:
        self._client: httpx.Client | None = None
        self._findings: list[FindingModel] = []

    def analyze(self, js_urls: list[str], target: str = "") -> list[dict[str, Any]]:
        logger.info("SOURCEMAP_ANALYZER_START scripts={}", len(js_urls))
        results: list[dict[str, Any]] = []

        with httpx.Client(timeout=15.0, verify=False) as client:
            self._client = client
            for js_url in js_urls:
                result = self._check_sourcemap(js_url, target)
                if result:
                    results.append(result)

        logger.info("SOURCEMAP_ANALYZER_DONE sourcemaps={}", len(results))
        return results

    def _check_sourcemap(self, js_url: str, target: str = "") -> dict[str, Any] | None:
        if not self._client:
            return None
        try:
            resp = self._client.get(js_url, headers={"User-Agent": "GhostMirror-BugBounty/1.0"})
            if resp.status_code != 200:
                return None
            content = resp.text
        except Exception as exc:
            logger.debug("SOURCEMAP_SKIP url={} reason={}", js_url, exc)
            return None

        match = SOURCEMAP_PATTERN.search(content)
        if not match:
            return None

        sourcemap_url = urljoin(js_url, match.group(1))
        result: dict[str, Any] = {
            "js_url": js_url,
            "sourcemap_url": sourcemap_url,
            "found": True,
            "exposed": False,
            "files": [],
            "endpoints": [],
            "comments": [],
            "routes": [],
        }

        try:
            sm_resp = self._client.get(
                sourcemap_url,
                headers={"User-Agent": "GhostMirror-BugBounty/1.0"},
                follow_redirects=False,
            )
            if sm_resp.status_code == 200:
                result["exposed"] = True
                self._parse_sourcemap(sm_resp.text, result, sourcemap_url, target)
        except Exception as exc:
            logger.debug("SOURCEMAP_FETCH_FAIL url={} reason={}", sourcemap_url, exc)

        return result

    def _parse_sourcemap(self, content: str, result: dict[str, Any], sourcemap_url: str, target: str) -> None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        sources = data.get("sources", [])
        result["files"] = sources

        api_pattern = re.compile(r"/api/|/graphql|/v\d+/|/rest/", re.IGNORECASE)
        route_pattern = re.compile(r"(?:path|route|component)\s*[:=]\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
        comment_pattern = re.compile(r"//\s*(TODO|FIXME|HACK|XXX|BUG|SECURITY)[:\s]*(.*)", re.IGNORECASE)

        all_endpoints = set()
        all_routes = set()
        all_comments = []

        for source in sources:
            if api_pattern.search(source):
                all_endpoints.add(source)

        sources_content = data.get("sourcesContent", [])
        for sc in sources_content:
            if not sc:
                continue
            for match in api_pattern.findall(sc):
                all_endpoints.add(match)
            for match in route_pattern.findall(sc):
                all_routes.add(match)
            for tag, text in comment_pattern.findall(sc):
                all_comments.append(f"{tag}: {text.strip()}")
            for match in re.findall(r'["\'](/[a-zA-Z0-9_/.-]+)["\']', sc):
                if any(kw in match.lower() for kw in ["api", "auth", "admin", "login", "user", "payment"]):
                    all_endpoints.add(match)

        result["endpoints"] = list(all_endpoints)
        result["routes"] = list(all_routes)
        result["comments"] = list(set(all_comments))

        if result["exposed"]:
            sev = FindingSeverity.HIGH if len(all_endpoints) > 5 or len(sources) > 10 else FindingSeverity.MEDIUM
            finding = FindingModel(
                title="Exposed Source Map",
                description=(
                    f"A source map file was discovered exposed at {sourcemap_url} "
                    f"containing {len(sources)} source files and {len(all_endpoints)} API endpoints. "
                    "Source maps expose application source code including business logic, API URLs, "
                    "and internal implementation details."
                ),
                severity=sev,
                target=target or sourcemap_url,
                evidence=f"Source map URL: {sourcemap_url}\nSource files found: {len(sources)}\nEndpoints exposed: {len(all_endpoints)}",
                recommendation="Remove source map files from production deployments. "
                "Configure your build tool to not generate source maps for production builds, "
                "or restrict access to .map files via web server configuration.",
                category="bug_bounty_sourcemap",
            )
            self._findings.append(finding)
            logger.info("SOURCEMAP_EXPOSED url={} files={} endpoints={}", sourcemap_url, len(sources), len(all_endpoints))

    def get_findings(self) -> list[FindingModel]:
        return self._findings
