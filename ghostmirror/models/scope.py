"""Pydantic models for engagement scope definitions (``scope.yaml``).

The scope file is the contract that bounds every action GhostMirror is allowed
to take against a target. It is validated strictly: an invalid or empty scope
must never be silently accepted.
"""

from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator

#: RFC-1123-ish hostname matcher (labels of 1-63 chars, at least two labels).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)

#: Allowed hosts for lab targets (localhost and RFC1918 loopback).
_LAB_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}

#: URL scheme matcher.
_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


class ScopeProjectInfo(BaseModel):
    """Identifies the engagement the scope belongs to."""

    client: str = Field(..., min_length=1, description="Client / organization name")
    name: str = Field(..., min_length=1, description="Engagement name")
    lab: bool = Field(
        False, description="When True, target is a local controlled lab environment"
    )


class ScopeTargets(BaseModel):
    """The in-scope assets. Anything not listed here is out of scope."""

    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(
        default_factory=list,
        description="Full URLs for lab targets (localhost / private IPs only)",
    )

    @field_validator("domains")
    @classmethod
    def _normalize_domains(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in value:
            domain = raw.strip().lower()
            if not domain:
                continue
            if not _DOMAIN_RE.match(domain):
                raise ValueError(f"Invalid domain in scope: {raw!r}")
            cleaned.append(domain)
        return cleaned

    @field_validator("ips")
    @classmethod
    def _normalize_ips(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in value:
            candidate = raw.strip()
            if not candidate:
                continue
            try:
                # Accept both single addresses and CIDR ranges.
                ipaddress.ip_network(candidate, strict=False)
            except ValueError as exc:  # noqa: PERF203 - explicit per-item error
                raise ValueError(f"Invalid IP/CIDR in scope: {raw!r}") from exc
            cleaned.append(candidate)
        return cleaned

    @field_validator("urls")
    @classmethod
    def _normalize_urls(cls, value: list[str]) -> list[str]:
        from urllib.parse import urlparse

        cleaned: list[str] = []
        for raw in value:
            url = raw.strip()
            if not url:
                continue
            if not _URL_RE.match(url):
                raise ValueError(f"Invalid URL in scope: {raw!r}")
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if host not in _LAB_ALLOWED_HOSTS and not cls._is_private_ip(host):
                raise ValueError(
                    f"URL host {host!r} is not allowed in lab scope. "
                    f"Only localhost and private IPs are permitted."
                )
            cleaned.append(url)
        return cleaned

    @staticmethod
    def _is_private_ip(host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            return addr.is_private
        except ValueError:
            return False


class AllowedTests(BaseModel):
    """Explicit allow-list of test categories permitted by the engagement.

    Defaults are intentionally conservative: passive/non-intrusive categories
    are enabled, while anything potentially intrusive or destructive is opt-in.
    """

    recon: bool = True
    ssl_scan: bool = True
    web_scan: bool = True
    port_scan: bool = True
    credential_audit: bool = False
    exploitation: bool = False
    destructive_tests: bool = False


class ScopeModel(BaseModel):
    """Top-level scope schema, mirroring ``scope.yaml``.

    Structural validation (required project fields, well-formed domains/IPs) is
    enforced here. The "must have at least one target" rule is intentionally a
    *runtime readiness* check (:attr:`has_targets`) rather than a schema
    invariant, so a freshly created project may exist before its targets are
    known while still producing a valid scope file.
    """

    project: ScopeProjectInfo
    targets: ScopeTargets = Field(default_factory=ScopeTargets)
    allowed_tests: AllowedTests = Field(default_factory=AllowedTests)

    @property
    def has_targets(self) -> bool:
        """True when at least one in-scope domain, IP or URL is defined."""

        return bool(self.targets.domains or self.targets.ips or self.targets.urls)
