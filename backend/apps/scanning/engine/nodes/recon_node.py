import logging
from typing import Dict, Any
from apps.scanning.engine.tools.registry import get_registry

logger = logging.getLogger(__name__)

def recon_specialist_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Tier-1 Recon Specialist Node — Read-Only discovery and endpoint mapping."""
    target_url = state.get("target_url", "")
    logger.info(f"[Recon Node] Executing discovery for target: {target_url}")
    
    registry = get_registry()
    discovered_endpoints = list(state.get("discovered_endpoints", []))
    cost = float(state.get("current_cost", 0.0))
    
    # Run subfinder via MCP
    subfinder_res = registry.run_tool_mcp("subfinder", target_url)
    if "result" in subfinder_res:
        for f in subfinder_res["result"].get("findings", []):
            discovered_endpoints.append({
                "url": f.get("title") or target_url,
                "source": "subfinder",
                "status": "active"
            })
            
    # Run httpx via MCP
    httpx_res = registry.run_tool_mcp("httpx", target_url)
    if "result" in httpx_res:
        for f in httpx_res["result"].get("findings", []):
            discovered_endpoints.append({
                "url": f.get("url") or target_url,
                "source": "httpx",
                "status": "alive",
                "metadata": f.get("metadata", {})
            })
            
    # Add target_url itself if endpoints list is empty
    if not discovered_endpoints:
        discovered_endpoints.append({"url": target_url, "source": "target_root", "status": "alive"})
        
    cost += 0.005  # Simulated LLM auto-summarization token cost
    logger.info(f"[Recon Node] Discovered {len(discovered_endpoints)} endpoints.")
    
    return {
        "discovered_endpoints": discovered_endpoints,
        "current_cost": cost,
        "flow_status": "recon_completed"
    }
