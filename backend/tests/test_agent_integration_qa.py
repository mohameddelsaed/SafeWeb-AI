"""
QA Phase D Integration Test Suite
Verifies D1 (Memory handoff lifecycle), D2 (Browser session persistence), and D3 (Scope enforcement pipeline).
"""
import pytest
import asyncio
from unittest.mock import patch, MagicMock
from apps.scanning.engine.scope.scope_manager import ScopeManager
from apps.ml.rag import ExploitMemoryRAG
from apps.scanning.engine.headless.browser_mcp import BrowserMCPServer


@patch('apps.ml.models.ExploitMemory.objects')
def test_d1_memory_handoff_lifecycle(mock_objects):
    """Verify D1: ExploitMemory state persistence across agent turns and resume after simulated restart."""
    mock_item = MagicMock()
    mock_item.id = "turn_1_sqli_id"
    mock_item.technology_stack = "PHP / DVWA"
    mock_item.vulnerability_class = "SQL Injection"
    mock_item.attack_strategy_summary = "Union-based SQLi against DVWA login"
    mock_item.successful_payload = "' UNION SELECT user, password FROM users#"
    
    # Simulate database retrieval after turn crash/resume
    mock_objects.all.side_effect = Exception("pgvector fallback")
    mock_objects.filter.return_value.__getitem__.return_value = [mock_item]
    
    # Query stored strategy from previous turn
    results = ExploitMemoryRAG.query_similar_strategies("SQL Injection", limit=5)
    assert len(results) == 1
    assert results[0]["vulnerability_class"] == "SQL Injection"
    assert results[0]["successful_payload"] == "' UNION SELECT user, password FROM users#"
    assert "DVWA" in results[0]["technology_stack"]


def test_d2_browser_session_persistence():
    """Verify D2: Browser session retainment and cookie simulation across navigation steps."""
    async def _run():
        server = BrowserMCPServer()
        
        # Turn 1: Navigate to target DVWA
        nav_res = await server.handle_request("browser_navigate", {"url": "http://127.0.0.1:8081/login.php"}, req_id=1)
        assert nav_res["result"]["status"] == "navigated"
        
        # Turn 2: Fill login credentials and submit within same session
        await server.handle_request("browser_fill", {"selector": "#username", "value": "admin"}, req_id=2)
        await server.handle_request("browser_fill", {"selector": "#password", "value": "password"}, req_id=3)
        await server.handle_request("browser_click", {"selector": "#submit"}, req_id=4)
        
        # Turn 3: Verify session cookie retention across navigation steps
        cookie_res = await server.handle_request("browser_extract_cookies", {}, req_id=5)
        cookies = cookie_res["result"]["cookies"]
        assert len(cookies) >= 1
        assert any(c["name"] == "session_token" for c in cookies)
        
        await server.close()
        
    asyncio.run(_run())


def test_d3_scope_enforcement_pipeline(monkeypatch):
    """Verify D3: Mixed target feed drops out-of-scope targets before forwarding to tool calls."""
    monkeypatch.setenv("ENFORCE_QA_SCOPE", "true")
    sm = ScopeManager(in_scope=["*"])
    
    mixed_targets = [
        "http://127.0.0.1:8081",
        "https://out-of-scope-evil.com",
        "http://localhost:3000",
        "https://google.com/admin",
        "http://target-webgoat:8080/WebGoat/login"
    ]
    
    in_scope, out_scope = sm.validate_targets(mixed_targets)
    
    # Verify exact boundary partitioning
    assert "http://127.0.0.1:8081" in in_scope
    assert "http://localhost:3000" in in_scope
    assert "http://target-webgoat:8080/WebGoat/login" in in_scope
    assert "https://out-of-scope-evil.com" in out_scope
    assert "https://google.com/admin" in out_scope
    assert len(in_scope) == 3
    assert len(out_scope) == 2
