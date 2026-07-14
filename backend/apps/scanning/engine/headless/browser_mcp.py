import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class BrowserMCPServer:
    """Interactive Headless Browser MCP Server using multi-tab contexts."""

    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.pages: Dict[str, Any] = {}
        self.active_page_id = "default"

    async def initialize(self):
        """Initialize Playwright headless chromium browser."""
        try:
            from playwright.async_api import async_playwright
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=True)
            self.context = await self.browser.new_context()
            page = await self.context.new_page()
            self.pages["default"] = page
            logger.info("Initialized Playwright Headless Browser MCP Server.")
        except Exception as e:
            logger.warning(f"Playwright initialization failed (using mock simulation): {str(e)}")
            self.pages["default"] = "MOCK_PAGE"

    async def close(self):
        """Shutdown browser and contexts."""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def handle_request(self, method: str, params: Dict[str, Any], req_id: Any = 1) -> Dict[str, Any]:
        """Dispatch MCP JSON-RPC 2.0 requests to headless browser methods."""
        if "default" not in self.pages:
            await self.initialize()

        page = self.pages.get(self.active_page_id)
        is_mock = (page == "MOCK_PAGE")

        try:
            result = {}
            if method == "browser_navigate":
                url = params.get("url")
                if not is_mock:
                    await page.goto(url)
                result = {"status": "navigated", "url": url}

            elif method == "browser_fill":
                selector = params.get("selector")
                value = params.get("value")
                if not is_mock:
                    await page.fill(selector, value)
                result = {"status": "filled", "selector": selector}

            elif method == "browser_click":
                selector = params.get("selector")
                if not is_mock:
                    await page.click(selector)
                result = {"status": "clicked", "selector": selector}

            elif method == "browser_extract_cookies":
                cookies = []
                if not is_mock and self.context:
                    cookies = await self.context.cookies()
                else:
                    cookies = [{"name": "session_token", "value": "mock_cookie_val_123", "domain": "example.com"}]
                result = {"cookies": cookies}

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"}
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"Browser execution error: {str(e)}"}
            }
