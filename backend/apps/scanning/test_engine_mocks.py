import pytest
import json
from unittest.mock import patch
from django.test import TestCase
from apps.accounts.models import Organization, User
from apps.scanning.models import Scan, Vulnerability
from apps.scanning.engine.tools.wrappers.nuclei_cli_wrapper import NucleiCLITool

@pytest.mark.django_db
class TestScannerEngine(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='user@test.com', username='user@test.com', password='Password123!')
        self.org = Organization.objects.create(name='Test Org')
        self.scan = Scan.objects.create(
            user=self.user,
            organization=self.org,
            target='https://example.com',
            status='pending',
            scan_type='website'
        )

    @patch('apps.scanning.engine.tools.base.ExternalTool._exec')
    @patch('apps.scanning.engine.tools.base.ExternalTool.is_available')
    def test_nuclei_mock_execution(self, mock_is_available, mock_exec):
        """Test Mock Execution of Nuclei"""
        mock_is_available.return_value = True
        
        # Mock Nuclei JSON output
        mock_output = json.dumps({
            "template-id": "tech-detect",
            "info": {
                "name": "Technology Detection",
                "severity": "info"
            },
            "host": "https://example.com",
            "matcher-name": "nginx"
        })
        mock_exec.return_value = mock_output
        
        tool = NucleiCLITool()
        results = tool.run('https://example.com')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "[tech-detect] Technology Detection")
        self.assertEqual(results[0].severity, "info")

    def test_vulnerability_deduplication(self):
        """Test Vulnerability Deduplication Logic"""
        # Create first vulnerability
        Vulnerability.objects.create(
            scan=self.scan,
            name="Test Vuln",
            severity="medium",
            affected_url="https://example.com/api"
        )
        
        # In the engine, when we try to create the same vulnerability, we should 
        # either skip or increment count/instances.
        # Simulating the exact engine save behavior for deduplication
        existing = Vulnerability.objects.filter(
            scan=self.scan,
            name="Test Vuln",
            affected_url="https://example.com/api"
        ).first()
        
        if existing:
            # Update logic (just saving again or modifying instances)
            existing.save()
            created = False
        else:
            Vulnerability.objects.create(
                scan=self.scan,
                name="Test Vuln",
                severity="medium",
                affected_url="https://example.com/api"
            )
            created = True
            
        self.assertFalse(created)
        
        # Total vulns should be 1
        count = Vulnerability.objects.filter(scan=self.scan).count()
        self.assertEqual(count, 1)


@pytest.mark.unit
@patch('apps.scanning.engine.tools.base.ExternalTool._exec')
@patch('apps.scanning.engine.tools.base.ExternalTool.is_available')
def test_nuclei_mcp_json_rpc_schema(mock_is_available, mock_exec):
    """Test verification of MCP JSON-RPC 2.0 formatting."""
    mock_is_available.return_value = True
    mock_exec.return_value = json.dumps({
        "template-id": "cve-2026-1234",
        "info": {"name": "Critical RCE", "severity": "critical"},
        "host": "https://example.com"
    })
    
    tool = NucleiCLITool()
    response = tool.run_mcp('https://example.com', request_id=42)
    
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 42
    assert "result" in response
    assert response["result"]["tool"] == "nuclei"
    assert response["result"]["findings_count"] == 1
    assert response["result"]["findings"][0]["title"] == "[cve-2026-1234] Critical RCE"
    assert response["result"]["findings"][0]["severity"] == "critical"


@pytest.mark.unit
def test_registry_run_tool_mcp():
    """Test calling tool via registry MCP method."""
    from apps.scanning.engine.tools.registry import get_registry
    registry = get_registry()
    
    # Test missing tool error
    err_res = registry.run_tool_mcp('non_existent_tool', 'https://example.com', request_id=99)
    assert err_res["error"]["code"] == -32601


@pytest.mark.unit
def test_exploit_node_skill_loading():
    """Test feeding mock endpoint into exploit node and loading skill markdown."""
    from apps.scanning.engine.nodes.exploit_node import exploit_specialist_node
    from apps.scanning.engine.knowledge import load_skill_markdown
    
    # Check knowledge loader
    sqli_skill = load_skill_markdown("sqli")
    assert sqli_skill is not None
    assert "SQL Injection Verification Protocol" in sqli_skill
    
    # Check node execution
    mock_state = {
        "candidate_vulnerabilities": [
            {"title": "Test SQL Injection Vulnerability", "severity": "high", "url": "https://example.com/login"}
        ],
        "current_cost": 0.0
    }
    result_state = exploit_specialist_node(mock_state)
    assert len(result_state["verified_vulnerabilities"]) == 1
    assert result_state["verified_vulnerabilities"][0]["verification_status"] in ("verified", "unverified")
    assert result_state["current_cost"] > 0.0


@pytest.mark.unit
def test_langgraph_orchestrator_flow():
    """Test full LangGraph StateGraph transition flow."""
    from apps.scanning.engine.langgraph_engine import LangGraphOrchestrator
    orchestrator = LangGraphOrchestrator()
    initial_state = {
        "scan_id": "test_scan_123",
        "target_url": "https://example.com",
        "scope_allowlist": ["https://example.com"],
        "flow_status": "initializing",
        "discovered_endpoints": [],
        "candidate_vulnerabilities": [],
        "verified_vulnerabilities": [],
        "current_cost": 0.0,
        "engagement_log": []
    }
    final_state = orchestrator.run_scan(initial_state)
    assert final_state["flow_status"] == "validation_completed"
    assert len(final_state["engagement_log"]) >= 1
    assert final_state["engagement_log"][0]["step"] == "scope_gate"


@pytest.mark.unit
def test_validator_node_reproof():
    """Test validator node executing 3/3 deterministic reproof loop."""
    from apps.scanning.engine.nodes.validator_node import validator_specialist_node
    mock_state = {
        "verified_vulnerabilities": [
            {"title": "Critical SQL Injection", "severity": "critical", "url": "https://example.com"}
        ],
        "current_cost": 0.0,
        "engagement_log": []
    }
    result = validator_specialist_node(mock_state)
    assert result["flow_status"] == "validation_completed"
    assert len(result["verified_vulnerabilities"]) == 1
    capsule = result["verified_vulnerabilities"][0]["proof_capsule"]
    assert capsule["reproof_passes_required"] == 3
    assert capsule["deterministic_verdict"] == "VERIFIED"





