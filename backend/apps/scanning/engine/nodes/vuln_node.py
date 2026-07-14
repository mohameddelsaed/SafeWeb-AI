import logging
from typing import Dict, Any
from apps.scanning.engine.tools.registry import get_registry

logger = logging.getLogger(__name__)

def vuln_scanner_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Tier-1 Vulnerability Scanner Node — Template scanning across discovered targets."""
    endpoints = state.get("discovered_endpoints", [])
    target_url = state.get("target_url", "")
    logger.info(f"[Vuln Node] Scanning {len(endpoints)} targets for template vulnerabilities.")
    
    registry = get_registry()
    candidates = list(state.get("candidate_vulnerabilities", []))
    cost = float(state.get("current_cost", 0.0))
    
    scan_targets = [ep.get("url", target_url) if isinstance(ep, dict) else str(ep) for ep in endpoints]
    if not scan_targets:
        scan_targets = [target_url]
        
    for url in scan_targets[:5]:  # Cap concurrent scans per node step
        nuclei_res = registry.run_tool_mcp("nuclei", url)
        if "result" in nuclei_res:
            for f in nuclei_res["result"].get("findings", []):
                candidates.append({
                    "title": f.get("title", "Unknown Vulnerability"),
                    "severity": f.get("severity", "info"),
                    "url": url,
                    "evidence": f.get("evidence", ""),
                    "verification_status": "candidate",
                    "source": "nuclei"
                })
                
    cost += 0.010  # Simulated token cost for vuln analysis
    logger.info(f"[Vuln Node] Found {len(candidates)} candidate vulnerabilities.")
    
    return {
        "candidate_vulnerabilities": candidates,
        "current_cost": cost,
        "flow_status": "vuln_scan_completed"
    }
