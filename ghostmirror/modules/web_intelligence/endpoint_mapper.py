from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ghostmirror.core.logger import get_logger
from ghostmirror.models.web_endpoint import HttpMethod, WebEndpoint, WebForm

logger = get_logger()

# Patterns for endpoint discovery
LINK_PATTERN = re.compile(r'<a\s[^>]*href=["\'](.*?)["\']', re.IGNORECASE)
FORM_PATTERN = re.compile(r'<form\s[^>]*action=["\'](.*?)["\']', re.IGNORECASE)
FORM_METHOD_PATTERN = re.compile(r'<form\s[^>]*method=["\'](.*?)["\']', re.IGNORECASE)
INPUT_PATTERN = re.compile(r'<input\s[^>]*name=["\'](.*?)["\']', re.IGNORECASE)
SCRIPT_PATTERN = re.compile(r'<script\s[^>]*src=["\'](.*?)["\']', re.IGNORECASE)
API_PATTERN = re.compile(r'/api/|/v\d+/|/graphql|/rest/', re.IGNORECASE)
STATIC_EXTENSIONS = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}


class EndpointMapper:
    def __init__(self, max_depth: int = 1) -> None:
        self.max_depth = max_depth
        self._visited: set[str] = set()
        self._endpoints: list[WebEndpoint] = []
        self._client: httpx.Client | None = None

    def discover(self, target_url: str) -> list[WebEndpoint]:
        logger.info("ENDPOINT_MAPPER_START target={} max_depth={}", target_url, self.max_depth)
        self._visited.clear()
        self._endpoints.clear()

        parsed = urlparse(target_url)
        self._base = f"{parsed.scheme}://{parsed.netloc}"

        with httpx.Client(timeout=15.0, follow_redirects=True, verify=False) as client:
            self._client = client
            self._crawl(target_url, depth=0)

        logger.info("ENDPOINT_MAPPER_DONE total={}", len(self._endpoints))
        return self._endpoints

    def _crawl(self, url: str, depth: int) -> None:
        if url in self._visited:
            return
        if depth > self.max_depth:
            return

        normalized = url.split("#")[0].split("?")[0].rstrip("/")
        if normalized in self._visited:
            return

        self._visited.add(url)
        self._visited.add(normalized)

        try:
            resp = self._client.get(url, headers={"User-Agent": "GhostMirror/1.0"})
        except Exception as exc:
            logger.debug("ENDPOINT_MAPPER_SKIP url={} reason={}", url, exc)
            return

        html = resp.text
        source_page = url

        endpoint = self._parse_endpoint(url, resp, html, source_page)
        self._endpoints.append(endpoint)

        if depth < self.max_depth:
            for link in LINK_PATTERN.findall(html):
                absolute = urljoin(url, link.strip())
                if self._is_same_origin(absolute) and not self._is_static(absolute):
                    self._crawl(absolute, depth + 1)

    def _parse_endpoint(self, url: str, resp: httpx.Response, html: str, source_page: str) -> WebEndpoint:
        parsed = urlparse(url)
        query_params = []
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    query_params.append(pair.split("=")[0])

        forms = []
        for form_action in FORM_PATTERN.findall(html):
            absolute_action = urljoin(url, form_action.strip())
            method_match = FORM_METHOD_PATTERN.search(html)
            method = method_match.group(1).upper() if method_match else "GET"
            inputs = INPUT_PATTERN.findall(html)
            forms.append(WebForm(action=absolute_action, method=method, inputs=inputs))

        tech_hints = []
        server = resp.headers.get("server", "")
        powered_by = resp.headers.get("x-powered-by", "")
        if server:
            tech_hints.append(server)
        if powered_by:
            tech_hints.append(powered_by)

        is_api = bool(API_PATTERN.search(url))
        is_auth = any(kw in url.lower() for kw in ["login", "signin", "auth", "register", "signup"])
        is_admin = any(kw in url.lower() for kw in ["admin", "dashboard", "adm"])
        is_static = self._is_static(url)

        return WebEndpoint(
            url=url,
            method=HttpMethod.GET,
            params=query_params,
            forms=forms,
            tech_hints=tech_hints,
            source_page=source_page,
            status_code=resp.status_code,
            content_type=resp.headers.get("content-type", ""),
            is_api=is_api,
            is_auth=is_auth,
            is_admin=is_admin,
            is_static=is_static,
            response_body_sample=html[:2000],
        )

    def _is_same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        return f"{parsed.scheme}://{parsed.netloc}" == self._base

    def _is_static(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)

    def get_script_urls(self, html: str, base_url: str) -> list[str]:
        urls = []
        for match in SCRIPT_PATTERN.findall(html):
            absolute = urljoin(base_url, match.strip())
            urls.append(absolute)
        return urls
