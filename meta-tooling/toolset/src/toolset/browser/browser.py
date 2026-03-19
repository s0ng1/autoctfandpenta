import os
from typing import Annotated
from playwright.async_api import async_playwright, BrowserContext

from core import tool, toolset, namespace

namespace()

@toolset()
class Browser:
    def __init__(self, url):
        self.url = url
        self.playwright = None
        self.browser_instance = None
    
    @tool()
    async def get_context(self) -> Annotated[BrowserContext, "BrowserContext in Playwright"]:
        """
        Returns the BrowserContext object from Playwright-Python.

        Examaple:
            You can use it to see which pages are available, open a new page to view its content, and then click on its elements:
            ```
            import toolset

            context = await toolset.browser.get_context()
            print(context.pages)
            page = await context.new_page()
            await page.goto("http://example.com")
            print(await page.locator("html").aria_snapshot())
            await page.get_by_role("link", name="Learn more").click()
            ```

            When testing a website for XSS vulnerabilities, do not use functions like alert and prompt; instead, use console.log:
            ```
            import toolset

            context = await toolset.browser.get_context()
            msgs = []
            async def handle_console(msg):
                msgs.append(msg)
            page = await context.new_page()
            page.on("console", handle_console)
            await page.goto("http://example.com")
            await page.evaluate("console.log(1);")
            print(msgs)
            ```

            Attention: Prioritize using existing page objects (context. pages) and avoid creating too many pages
        """

        if not self.browser_instance:
            self.playwright = await async_playwright().start()
            self.browser_instance = await self.playwright.chromium.connect_over_cdp(self.url)

        contexts = self.browser_instance.contexts
        if contexts:
            return contexts[0]
        else:
            return await self.browser_instance.new_context()

    async def _get_or_create_page(self):
        context = await self.get_context()
        return context.pages[0] if context.pages else await context.new_page()

    @tool()
    async def open_page(self, url: str) -> None:
        """Open a page in the existing browser context."""
        page = await self._get_or_create_page()
        await page.goto(url)

    @tool()
    async def get_page_snapshot(self) -> str:
        """Return a text snapshot of the active page."""
        page = await self._get_or_create_page()
        return await page.locator("html").inner_text()

    @tool()
    async def get_dom_excerpt(self, selector: str) -> str:
        """Return the outer HTML of the first matching DOM node."""
        page = await self._get_or_create_page()
        locator = page.locator(selector).first
        if await locator.count() == 0:
            return ""
        return await locator.evaluate("(node) => node.outerHTML")

    @tool()
    async def wait_for_network_idle(self, timeout: int = 10) -> bool:
        """Wait for the active page to reach Playwright's networkidle state."""
        page = await self._get_or_create_page()
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout * 1000)
            return True
        except Exception:
            return False

   

   
