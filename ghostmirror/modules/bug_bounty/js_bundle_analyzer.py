from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urljoin

import httpx

from ghostmirror.core.logger import get_logger
from ghostmirror.models.js_bundle_profile import JSBundleProfile

logger = get_logger()

API_PATTERNS = re.compile(
    r'["\'](/(?:api|graphql|rest|v\d+|auth|login|signin|register|signup|admin|dashboard|'
    r"user|users|profile|account|basket|cart|checkout|payment|order|invoice|"
    r"upload|download|export|import|logout)[^\"']*)['\"]",
    re.IGNORECASE,
)

SECRET_PATTERNS = re.compile(
    r"(?:api[_-]?key|secret|token|password|apikey|bearer|jwt|auth[_-]?token|"
    r"firebase|stripe[_-]?pk|sentry[_-]?dsn|supabase[_-]?url|google[_-]?maps[_-]?key)"
    r"\s*[:=]\s*[\"']([^\"']{8,})[\"']",
    re.IGNORECASE,
)

COMMENT_PATTERNS = re.compile(
    r"//\s*(TODO|FIXME|HACK|XXX|BUG|WORKAROUND|REVIEW|OPTIMIZE|NOTE|SECURITY)[:\s]*(.*)",
    re.IGNORECASE,
)

ROUTE_PATTERNS = re.compile(
    r"(?:path|route|component)\s*[:=]\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

FETCH_PATTERNS = re.compile(
    r"fetch\([\"']([^\"']+)[\"']|axios\.(?:get|post|put|delete|patch)\([\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

INTERESTING_PATTERNS = {
    "auth": re.compile(r"(login|signin|register|signup|logout|auth|oauth|sso)", re.IGNORECASE),
    "upload": re.compile(r"(upload|import|importar)", re.IGNORECASE),
    "download": re.compile(r"(download|export|exportar)", re.IGNORECASE),
    "admin": re.compile(r"(admin|dashboard|adm|backoffice)", re.IGNORECASE),
    "debug": re.compile(r"(debug|test|staging|dev|sandbox)", re.IGNORECASE),
    "payment": re.compile(r"(payment|checkout|cart|basket|invoice|order|billing)", re.IGNORECASE),
    "feature": re.compile(r"(feature[_-]?flag|enabled|disabled|beta|alpha|experimental)", re.IGNORECASE),
}

FRONTEND_ROUTES = re.compile(
    r"(?:path|route|router|navigate|push)\s*[:=\(]\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


class JSBundleAnalyzer:
    def __init__(self) -> None:
        self._client: httpx.Client | None = None

    def analyze(self, js_urls: list[str]) -> list[JSBundleProfile]:
        logger.info("JS_BUNDLE_ANALYZER_START bundles={}", len(js_urls))
        profiles: list[JSBundleProfile] = []

        with httpx.Client(timeout=15.0, verify=False) as client:
            self._client = client
            for js_url in js_urls:
                profile = self._analyze_bundle(js_url)
                if profile:
                    profiles.append(profile)

        logger.info("JS_BUNDLE_ANALYZER_DONE profiles={}", len(profiles))
        return profiles

    def _analyze_bundle(self, js_url: str) -> JSBundleProfile | None:
        if not self._client:
            return None
        try:
            resp = self._client.get(js_url, headers={"User-Agent": "GhostMirror-BugBounty/1.0"})
            if resp.status_code != 200:
                return None
            content = resp.text
        except Exception as exc:
            logger.debug("JS_BUNDLE_SKIP url={} reason={}", js_url, exc)
            return None

        profile = JSBundleProfile(
            url=js_url,
            size=len(content),
            content_hash=hashlib.md5(content.encode()).hexdigest(),
        )

        endpoints = list(set(API_PATTERNS.findall(content)))
        profile.endpoints = [e.strip("'\"") for e in endpoints]

        secrets_raw = SECRET_PATTERNS.findall(content)
        profile.secrets = list(set(s for s in secrets_raw if len(s) >= 8))

        comments = COMMENT_PATTERNS.findall(content)
        profile.comments = list(set(f"{tag}: {text.strip()}" for tag, text in comments))

        routes_raw = ROUTE_PATTERNS.findall(content) + FRONTEND_ROUTES.findall(content) + FETCH_PATTERNS.findall(content)
        flat_routes = []
        for r in routes_raw:
            if isinstance(r, tuple):
                flat_routes.extend([x for x in r if x])
            else:
                flat_routes.append(r)
        profile.routes = list(set(flat_routes))

        source_map_match = re.search(r"sourceMappingURL=([^\s'\"]+)", content)
        if source_map_match:
            profile.source_map_present = True
            profile.source_map_url = urljoin(js_url, source_map_match.group(1))

        feature_flags = []
        for flag_type, pattern in INTERESTING_PATTERNS.items():
            if pattern.search(content):
                feature_flags.append(flag_type)
        profile.feature_flags = list(set(feature_flags))

        return profile

    def get_all_endpoints(self, profiles: list[JSBundleProfile]) -> list[str]:
        endpoints = set()
        for p in profiles:
            endpoints.update(p.endpoints)
        return sorted(endpoints)

    def get_all_routes(self, profiles: list[JSBundleProfile]) -> list[str]:
        routes = set()
        for p in profiles:
            routes.update(p.routes)
        return sorted(routes)
