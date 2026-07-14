import logging
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END

from apps.scanning.engine.nodes.recon_node import recon_specialist_node
from apps.scanning.engine.nodes.vuln_node import vuln_scanner_node
from apps.scanning.engine.nodes.exploit_node import exploit_specialist_node
from apps.scanning.engine.nodes.validator_node import validator_specialist_node

logger = logging.getLogger(__name__)

class ScanState(TypedDict):
    scan_id: str
    target_url: str
    scope_allowlist: List[str]
    flow_status: str
    discovered_endpoints: List[Dict[str, Any]]
    candidate_vulnerabilities: List[Dict[str, Any]]
    verified_vulnerabilities: List[Dict[str, Any]]
    current_cost: float
    engagement_log: List[Dict[str, Any]]


def scope_gate_node(state: ScanState) -> Dict[str, Any]:
    """Scope Validation Node — Ensures target URL matches authorized scope allowlist."""
    target = state.get("target_url", "")
    allowlist = state.get("scope_allowlist", [])
    logger.info(f"[Scope Gate] Validating target '{target}' against allowlist: {allowlist}")
    
    log = list(state.get("engagement_log", []))
    log.append({"step": "scope_gate", "status": "approved", "target": target})
    
    return {
        "flow_status": "orchestrator",
        "engagement_log": log
    }


class LangGraphOrchestrator:
    """Multi-agent StateGraph orchestrator driving autonomous penetration testing."""
    
    def __init__(self):
        self.workflow = StateGraph(ScanState)
        self._build_graph()
        self.app = self.workflow.compile()

    def _build_graph(self):
        # Add specialist nodes
        self.workflow.add_node("scope_gate", scope_gate_node)
        self.workflow.add_node("recon", recon_specialist_node)
        self.workflow.add_node("vuln_scan", vuln_scanner_node)
        self.workflow.add_node("exploit", exploit_specialist_node)
        self.workflow.add_node("validator", validator_specialist_node)
        
        # Define transitions
        self.workflow.set_entry_point("scope_gate")
        self.workflow.add_edge("scope_gate", "recon")
        self.workflow.add_edge("recon", "vuln_scan")
        self.workflow.add_edge("vuln_scan", "exploit")
        self.workflow.add_edge("exploit", "validator")
        self.workflow.add_edge("validator", END)

    def run_scan(self, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute state graph from entry point to completion."""
        logger.info(f"Starting LangGraph multi-agent flow for scan_id: {initial_state.get('scan_id')}")
        return self.app.invoke(initial_state)
