from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import urlparse

from ghostmirror.core.exceptions import OutOfScopeError, ScopeViolationError
from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager

logger = get_logger()


class BountyScopeGuard:
    def __init__(
        self,
        project_path: Path | str | None = None,
        max_pages: int = 10,
        max_depth: int = 2,
        timeout: int = 30,
        rate_limit_delay: float = 1.0,
    ) -> None:
        self.project_path = Path(project_path) if project_path else None
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._request_count = 0
        self._last_request_time = 0.0
        self._scope_manager = ScopeManager()
        self._scope = None

    def load_scope(self) -> None:
        if not self.project_path:
            return
        scope_path = self.project_path / ScopeManager.SCOPE_FILENAME
        if scope_path.exists():
            self._scope = self._scope_manager.load_scope(scope_path)

    def check_url(self, url: str) -> bool:
        if not self._scope:
            return True
        parsed = urlparse(url)
        host = parsed.hostname or ""
        for domain in self._scope.targets.domains:
            if host == domain or host.endswith("." + domain):
                return True
        for allowed_url in self._scope.targets.urls:
            if url.startswith(allowed_url.rstrip("/")):
                return True
        return False

    def enforce_scope(self, url: str) -> None:
        if not self.check_url(url):
            raise OutOfScopeError(f"URL {url} is out of scope")

    def check_rate_limit(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()
        self._request_count += 1

    def check_max_pages(self, current_count: int) -> bool:
        if current_count >= self.max_pages:
            logger.info("Max pages reached: {}", self.max_pages)
            return False
        return True

    def check_max_depth(self, current_depth: int) -> bool:
        if current_depth > self.max_depth:
            return False
        return True

    def sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        sensitive = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "token", "api-key"}
        sanitized = {}
        for key, value in headers.items():
            if key.lower() in sensitive:
                sanitized[key] = self._redact(value)
            else:
                sanitized[key] = value
        return sanitized

    def _redact(self, value: str) -> str:
        if len(value) <= 8:
            return "****"
        return value[:4] + "****" + value[-4:]
