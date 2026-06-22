from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.core.logger import get_logger
from ghostmirror.models.crawled_route import CrawledRoute
from ghostmirror.modules.bug_bounty.browser_runner import BrowserRunner
from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard

logger = get_logger()


class HeadlessCrawler:
    def __init__(
        self,
        max_pages: int = 10,
        max_depth: int = 2,
        timeout: int = 30,
        rate_limit: float = 1.0,
    ) -> None:
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._routes: list[CrawledRoute] = []
        self._visited: set[str] = set()
        self._captured_requests: list[dict[str, Any]] = []
        self._captured_forms: list[dict[str, Any]] = []

    def crawl(
        self,
        target_url: str,
        scope_guard: BountyScopeGuard | None = None,
    ) -> list[CrawledRoute]:
        runner = BrowserRunner(headless=True, timeout=self.timeout * 1000)
        if not runner.check_playwright():
            raise ToolNotFoundError(
                "Playwright não encontrado. Instale com: pip install playwright && python -m playwright install chromium"
            )

        try:
            asyncio.run(self._async_crawl(runner, target_url, scope_guard))
        except ToolNotFoundError:
            raise
        except Exception as exc:
            logger.warning("HEADLESS_CRAWL_ERROR target={} error={}", target_url, exc)

        self._routes.sort(key=lambda r: r.timestamp)
        return self._routes

    async def _async_crawl(
        self,
        runner: BrowserRunner,
        target_url: str,
        scope_guard: BountyScopeGuard | None = None,
    ) -> None:
        await runner.launch()
        self._captured_requests = await runner.intercept_requests()
        try:
            await self._crawl_recursive(runner, target_url, depth=0, scope_guard=scope_guard)
        finally:
            await runner.close()

    async def _crawl_recursive(
        self,
        runner: BrowserRunner,
        url: str,
        depth: int = 0,
        scope_guard: BountyScopeGuard | None = None,
    ) -> None:
        normalized = url.split("#")[0].split("?")[0].rstrip("/")
        if normalized in self._visited:
            return
        if not scope_guard.check_max_depth(depth):
            return
        if not scope_guard.check_max_pages(len(self._routes)):
            return
        if scope_guard:
            scope_guard.check_rate_limit()
            try:
                scope_guard.enforce_scope(url)
            except Exception:
                return

        self._visited.add(normalized)
        logger.info("HEADLESS_CRAWL url={} depth={}", url, depth)

        try:
            page_info = await runner.navigate(url)
        except Exception as exc:
            logger.debug("HEADLESS_CRAWL_SKIP url={} reason={}", url, exc)
            return

        route = CrawledRoute(
            url=page_info.get("url", url),
            title=page_info.get("title", ""),
            status=page_info.get("status", 0),
            method="GET",
            source="headless",
            route_type="spa",
            discovered_from=url,
        )
        self._routes.append(route)

        # Capture rendered forms from the page
        try:
            forms = await runner.get_forms()
            for f in forms:
                self._captured_forms.append(f)
        except Exception:
            pass

        if depth < self.max_depth:
            for link in await runner.get_links():
                if link and link.startswith("http"):
                    await self._crawl_recursive(runner, link, depth + 1, scope_guard)

    def get_routes(self) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in self._routes]

    def get_captured_requests(self) -> list[dict[str, Any]]:
        return self._captured_requests

    def get_captured_forms(self) -> list[dict[str, Any]]:
        return self._captured_forms
