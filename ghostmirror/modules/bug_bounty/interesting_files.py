from __future__ import annotations

from typing import Any

import httpx

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity

logger = get_logger()

INTERESTING_PATHS = [
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/debug",
    "/phpinfo.php",
]


class InterestingFiles:
    def __init__(self) -> None:
        self._findings: list[FindingModel] = []
        self._results: list[dict[str, Any]] = []

    def check(self, base_url: str, scope_guard: BountyScopeGuard | None = None) -> list[dict[str, Any]]:
        logger.info("INTERESTING_FILES_CHECK base={}", base_url)
        base = base_url.rstrip("/")

        with httpx.Client(timeout=10.0, verify=False, follow_redirects=False) as client:
            for path in INTERESTING_PATHS:
                if scope_guard:
                    try:
                        scope_guard.enforce_scope(base + path)
                    except Exception:
                        continue

                try:
                    scope_guard and scope_guard.check_rate_limit()
                except Exception:
                    pass

                try:
                    resp = client.get(
                        base + path,
                        headers={"User-Agent": "GhostMirror-BugBounty/1.0"},
                    )
                    entry: dict[str, Any] = {
                        "path": path,
                        "url": base + path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "found": resp.status_code < 400,
                        "size": len(resp.content),
                    }
                    self._results.append(entry)

                    if entry["found"]:
                        sev = FindingSeverity.MEDIUM
                        if path in ("/.env", "/.git/config", "/backup.zip"):
                            sev = FindingSeverity.HIGH

                        finding = FindingModel(
                            title=f"Interesting File Exposed: {path}",
                            description=(
                                f"The file {path} was found at {base + path} "
                                f"with status {resp.status_code}. "
                                f"This file may expose sensitive information."
                            ),
                            severity=sev,
                            target=base,
                            evidence=f"URL: {base + path}\nStatus: {resp.status_code}\nContent-Type: {resp.headers.get('content-type', '')}",
                            recommendation=f"Restrict access to {path} on the web server. "
                            "Remove sensitive files from the document root.",
                            category="bug_bounty_interesting_file",
                        )
                        self._findings.append(finding)
                        logger.info("INTERESTING_FILE_FOUND path={} status={}", path, resp.status_code)

                except Exception as exc:
                    logger.debug("INTERESTING_FILE_SKIP path={} reason={}", path, exc)

        logger.info("INTERESTING_FILES_DONE checked={} found={}", len(INTERESTING_PATHS), sum(1 for r in self._results if r["found"]))
        return self._results

    def get_findings(self) -> list[FindingModel]:
        return self._findings
