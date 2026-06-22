from __future__ import annotations

import re
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ghostmirror.core.logger import get_logger
from ghostmirror.models.subdomain_profile import SubdomainProfile

logger = get_logger()

URL_HOSTNAME_PATTERN = re.compile(r'https?://([a-zA-Z0-9.-]+)', re.IGNORECASE)


class SubdomainDiscovery:
    def __init__(self) -> None:
        self._subdomains: list[SubdomainProfile] = []
        self._seen: set[str] = set()

    def discover(
        self,
        domain: str,
        html_content: str = "",
        js_urls: list[str] | None = None,
    ) -> list[SubdomainProfile]:
        logger.info("SUBDOMAIN_DISCOVERY_START domain={}", domain)

        self._extract_from_html(html_content, domain)
        self._extract_from_js(js_urls or [], domain)
        self._try_ct_logs(domain)

        logger.info("SUBDOMAIN_DISCOVERY_DONE total={}", len(self._subdomains))
        return self._subdomains

    def _extract_from_html(self, html: str, base_domain: str) -> None:
        matches = URL_HOSTNAME_PATTERN.findall(html)
        for hostname in matches:
            if hostname != base_domain and (hostname.endswith("." + base_domain) or base_domain.endswith("." + hostname)):
                self._add_subdomain(hostname, "html_link")

    def _extract_from_js(self, js_urls: list[str], base_domain: str) -> None:
        for url in js_urls:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            if hostname != base_domain and hostname.endswith("." + base_domain):
                self._add_subdomain(hostname, "js_bundle")

    def _try_ct_logs(self, domain: str) -> None:
        try:
            import httpx
            resp = httpx.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=10.0,
                headers={"User-Agent": "GhostMirror-BugBounty/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data if isinstance(data, list) else []:
                    name = entry.get("name_value", "")
                    for host in name.split("\n"):
                        host = host.strip().lower()
                        if host.endswith("." + domain):
                            self._add_subdomain(host, "certificate_transparency")
                        elif host == domain:
                            pass
        except Exception as exc:
            logger.debug("CT_LOG_SKIP domain={} reason={}", domain, exc)

    def _add_subdomain(self, hostname: str, source: str) -> None:
        hostname = hostname.strip().lower()
        if hostname in self._seen:
            return
        self._seen.add(hostname)

        ips = []
        try:
            ips = list(set(socket.gethostbyname_ex(hostname)[2]))
        except Exception:
            pass

        profile = SubdomainProfile(
            hostname=hostname,
            source=source,
            resolved_ips=ips,
            http_status=0,
            discovered_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self._subdomains.append(profile)

    def get_subdomains(self) -> list[SubdomainProfile]:
        return self._subdomains
