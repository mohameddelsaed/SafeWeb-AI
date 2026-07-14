import pytest
import asyncio
from apps.scanning.engine.headless.browser_mcp import BrowserMCPServer

@pytest.mark.unit
def test_browser_mcp_server_flow():
    """Test interactive browser MCP JSON-RPC navigation, form filling, and cookie extraction."""
    async def _run():
        server = BrowserMCPServer()
        
        # Test navigation
        nav_res = await server.handle_request("browser_navigate", {"url": "https://example.com/login"}, req_id=1)
        assert nav_res["jsonrpc"] == "2.0"
        assert nav_res["result"]["status"] == "navigated"
        
        # Test form fill
        fill_res = await server.handle_request("browser_fill", {"selector": "#username", "value": "admin"}, req_id=2)
        assert fill_res["result"]["status"] == "filled"
        
        # Test click
        click_res = await server.handle_request("browser_click", {"selector": "#submit"}, req_id=3)
        assert click_res["result"]["status"] == "clicked"
        
        # Test extract cookies
        cookie_res = await server.handle_request("browser_extract_cookies", {}, req_id=4)
        assert len(cookie_res["result"]["cookies"]) >= 1
        assert cookie_res["result"]["cookies"][0]["name"] == "session_token"
        
        await server.close()
        
    asyncio.run(_run())
