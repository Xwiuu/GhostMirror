from __future__ import annotations

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.core.logger import get_logger

logger = get_logger()


class BrowserRunner:
    def __init__(self, headless: bool = True, timeout: int = 30000) -> None:
        self.headless = headless
        self.timeout = timeout
        self._browser = None
        self._context = None
        self._page = None

    def check_playwright(self) -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    async def launch(self) -> None:
        if not self.check_playwright():
            raise ToolNotFoundError(
                "Playwright não encontrado. Instale com: pip install playwright && python -m playwright install chromium"
            )
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )
        self._context = await self._browser.new_context(
            user_agent="GhostMirror-BugBounty/1.0",
            viewport={"width": 1280, "height": 720},
        )
        self._page = await self._context.new_page()

    async def navigate(self, url: str) -> dict:
        if not self._page:
            raise RuntimeError("Browser not launched")
        response = await self._page.goto(url, timeout=self.timeout, wait_until="networkidle")
        status = response.status if response else 0
        title = await self._page.title()
        content = await self._page.content()
        return {"status": status, "title": title, "content": content, "url": self._page.url}

    async def get_links(self) -> list[str]:
        if not self._page:
            return []
        return await self._page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")

    async def get_forms(self) -> list[dict]:
        if not self._page:
            return []
        return await self._page.evaluate("""
            () => Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.elements).map(e => ({name: e.name, type: e.type}))
            }))
        """)

    async def close(self) -> None:
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def intercept_requests(self) -> list[dict]:
        captured = []

        def _handle_request(request):
            captured.append({
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "headers": dict(request.headers),
                "post_data": request.post_data,
            })

        if self._page:
            self._page.on("request", _handle_request)
        return captured
