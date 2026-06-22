from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.modules.bug_bounty.headless_crawler import HeadlessCrawler
from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard


class TestHeadlessCrawler:
    def test_init(self) -> None:
        crawler = HeadlessCrawler(max_pages=5, max_depth=1, timeout=15)
        assert crawler.max_pages == 5
        assert crawler.max_depth == 1
        assert crawler.timeout == 15
        assert crawler._routes == []
        assert crawler._visited == set()

    @patch("ghostmirror.modules.bug_bounty.headless_crawler.BrowserRunner.check_playwright")
    def test_crawl_playwright_missing(self, mock_check: MagicMock) -> None:
        mock_check.return_value = False
        crawler = HeadlessCrawler()
        with pytest.raises(ToolNotFoundError):
            crawler.crawl("https://example.com")

    @patch("ghostmirror.modules.bug_bounty.headless_crawler.BrowserRunner.check_playwright")
    @patch("ghostmirror.modules.bug_bounty.headless_crawler.asyncio.run")
    def test_crawl_success_empty(self, mock_asyncio_run: MagicMock, mock_check: MagicMock) -> None:
        mock_check.return_value = True
        crawler = HeadlessCrawler()
        result = crawler.crawl("https://example.com")
        assert result == []

    @patch("ghostmirror.modules.bug_bounty.headless_crawler.BrowserRunner.check_playwright")
    @patch("ghostmirror.modules.bug_bounty.headless_crawler.asyncio.run")
    def test_crawl_with_scope_guard(self, mock_asyncio_run: MagicMock, mock_check: MagicMock) -> None:
        mock_check.return_value = True
        scope_guard = MagicMock(spec=BountyScopeGuard)
        scope_guard.check_max_depth.return_value = True
        scope_guard.check_max_pages.return_value = True
        scope_guard.check_rate_limit.return_value = None
        scope_guard.enforce_scope.return_value = None

        crawler = HeadlessCrawler()
        result = crawler.crawl("https://example.com", scope_guard)
        assert result == []

    def test_get_routes_empty(self) -> None:
        crawler = HeadlessCrawler()
        assert crawler.get_routes() == []

    def test_get_captured_requests_empty(self) -> None:
        crawler = HeadlessCrawler()
        assert crawler.get_captured_requests() == []

    def test_get_captured_forms_empty(self) -> None:
        crawler = HeadlessCrawler()
        assert crawler.get_captured_forms() == []

    @patch("ghostmirror.modules.bug_bounty.headless_crawler.BrowserRunner")
    def test_async_crawl_with_mock_runner(self, MockRunner: MagicMock) -> None:
        import asyncio
        runner = MockRunner()
        runner.check_playwright.return_value = True
        runner.launch = AsyncMock()
        runner.close = AsyncMock()
        runner.navigate = AsyncMock(return_value={
            "url": "https://example.com",
            "title": "Test",
            "status": 200,
        })
        runner.get_links = AsyncMock(return_value=[])
        runner.get_forms = AsyncMock(return_value=[])
        runner.intercept_requests = AsyncMock(return_value=[])

        scope_guard = MagicMock(spec=BountyScopeGuard)
        scope_guard.check_max_depth.return_value = True
        scope_guard.check_max_pages.return_value = True
        scope_guard.check_rate_limit.return_value = None
        scope_guard.enforce_scope.return_value = None

        crawler = HeadlessCrawler(max_pages=5, max_depth=1, timeout=15)

        with patch.object(crawler, "_async_crawl") as mock_async:
            mock_async.return_value = None
            result = crawler.crawl("https://example.com", scope_guard)
            assert result == []

    @patch("ghostmirror.modules.bug_bounty.headless_crawler.asyncio.run")
    @patch("ghostmirror.modules.bug_bounty.headless_crawler.BrowserRunner.check_playwright")
    def test_max_pages_limit(self, mock_check: MagicMock, mock_run: MagicMock) -> None:
        mock_check.return_value = True
        crawler = HeadlessCrawler(max_pages=2, max_depth=3)
        scope_guard = MagicMock(spec=BountyScopeGuard)
        scope_guard.check_max_depth.side_effect = lambda d: d <= 3
        scope_guard.check_max_pages.side_effect = lambda c: c < 2
        scope_guard.check_rate_limit.return_value = None
        scope_guard.enforce_scope.return_value = None

        with patch.object(crawler, "_async_crawl") as mock_async:
            crawler.crawl("https://example.com", scope_guard)

    @patch("ghostmirror.modules.bug_bounty.headless_crawler.asyncio.run")
    @patch("ghostmirror.modules.bug_bounty.headless_crawler.BrowserRunner.check_playwright")
    def test_max_depth_limit(self, mock_check: MagicMock, mock_run: MagicMock) -> None:
        mock_check.return_value = True
        crawler = HeadlessCrawler(max_pages=10, max_depth=1)
        scope_guard = MagicMock(spec=BountyScopeGuard)
        scope_guard.check_max_depth.side_effect = lambda d: d <= 1
        scope_guard.check_max_pages.side_effect = lambda c: True
        scope_guard.check_rate_limit.return_value = None
        scope_guard.enforce_scope.return_value = None

        with patch.object(crawler, "_async_crawl") as mock_async:
            crawler.crawl("https://example.com", scope_guard)
