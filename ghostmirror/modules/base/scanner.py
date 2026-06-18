"""Base abstract class and validation exceptions for all GhostMirror scanners."""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.models.scope import ScopeModel
from ghostmirror.modules.findings.manager import FindingsManager
from ghostmirror.modules.models.finding import (
    FindingModel,
    FindingSeverity,
    ScanResultModel,
)

logger = get_logger()


from ghostmirror.core.exceptions import OutOfScopeError, ScannerError


def normalize_target(target: str) -> str:
    """Extract domain/IP from target string. Handles URLs, hostnames, ports, and brackets."""
    if not target.startswith(("http://", "https://")):
        url_to_parse = f"http://{target}"
    else:
        url_to_parse = target

    try:
        parsed = urlparse(url_to_parse)
        host = parsed.hostname
        if host:
            return host.lower().strip()
    except Exception:
        pass

    cleaned = target.strip().lower()
    if ":" in cleaned:
        if cleaned.startswith("[") and "]" in cleaned:
            idx = cleaned.find("]")
            return cleaned[1:idx]
        parts = cleaned.split(":")
        if parts[-1].isdigit():
            return ":".join(parts[:-1])
    return cleaned


class ScannerBase(ABC):
    """Abstract Base Class for all vulnerability and security scanners in GhostMirror.

    Provides common functionality for scope validation, logging, and findings saving,
    while enforcing scanner implementations via ABC.
    """

    def __init__(
        self,
        project_path: Path | str,
        target: str,
        scope_manager: ScopeManager | None = None,
        findings_manager: FindingsManager | None = None,
    ) -> None:
        self.project_path = Path(project_path)
        self.target = target.strip()
        self.scope_manager = scope_manager or ScopeManager()
        self.findings_manager = findings_manager or FindingsManager(self.project_path)

    def validate_scope(self) -> None:
        """Validate whether the target is authorized in the project's scope file."""
        scope_path = self.project_path / ScopeManager.SCOPE_FILENAME
        if not scope_path.exists():
            logger.error("SCOPE_FILE_MISSING path={}", scope_path)
            raise FileNotFoundError(f"Scope file not found: {scope_path}")

        scope = self.scope_manager.load_scope(scope_path)
        
        # Check if the scope defines any targets to test
        if not self.scope_manager.is_ready_for_testing(scope):
            logger.error("SCOPE_NOT_READY path={}", scope_path)
            raise OutOfScopeError("Scope is not ready for testing (no targets defined).")

        normalized = normalize_target(self.target)
        in_scope = False

        # 1. Check domains (exact matches or subdomains)
        for domain in scope.targets.domains:
            if normalized == domain or normalized.endswith("." + domain):
                in_scope = True
                break

        # 2. Check IPs and subnets
        if not in_scope:
            try:
                target_ip = ipaddress.ip_address(normalized)
                for ip_net_str in scope.targets.ips:
                    net = ipaddress.ip_network(ip_net_str, strict=False)
                    if target_ip in net:
                        in_scope = True
                        break
            except ValueError:
                # Not an IP address, skip IP validation
                pass

        # 3. Check URLs (lab targets)
        if not in_scope:
            for url in scope.targets.urls:
                parsed_host = urlparse(url).hostname or ""
                if normalized == parsed_host:
                    in_scope = True
                    break

        if not in_scope:
            logger.error(
                "TARGET_OUT_OF_SCOPE target={} normalized={} project={}",
                self.target,
                normalized,
                self.project_path.name,
            )
            raise OutOfScopeError(
                f"Target {self.target!r} (normalized: {normalized!r}) is not in scope "
                f"for project {self.project_path.name!r}."
            )

        logger.info(
            "SCOPE_VALIDATION_SUCCESS target={} normalized={} project={}",
            self.target,
            normalized,
            self.project_path.name,
        )

    def save_findings(self, scan_result: ScanResultModel) -> None:
        """Persist findings to project storage using FindingsManager."""
        self.findings_manager.save_findings(self.get_metadata()["name"], scan_result)

    def calculate_statistics(self, findings: list[FindingModel]) -> dict[str, int]:
        """Compute summary statistics for generated findings."""
        stats = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for finding in findings:
            sev = finding.severity.value.lower()
            if sev in stats:
                stats[sev] += 1
        return stats

    @abstractmethod
    def run(self) -> ScanResultModel:
        """Execute the scanner, validating scope, running tests, saving findings, and returning the result."""
        pass

    @abstractmethod
    def get_metadata(self) -> dict[str, Any]:
        """Return a dictionary of metadata describing the scanner (e.g. name, version)."""
        pass
