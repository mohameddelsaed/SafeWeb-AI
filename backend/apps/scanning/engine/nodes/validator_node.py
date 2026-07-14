import logging
from typing import Dict, Any
from apps.scanning.engine.verification import VerificationOracle
from apps.ml.rag import ExploitMemoryRAG

logger = logging.getLogger(__name__)

def validator_specialist_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """PoC Validator Agent Node — Executes 3/3 deterministic re-proof loop."""
    verified_input = state.get("verified_vulnerabilities", [])
    logger.info(f"[Validator Node] Running Oracle re-proof on {len(verified_input)} findings.")
    
    final_verified = []
    cost = float(state.get("current_cost", 0.0))
    log = list(state.get("engagement_log", []))
    
    for item in verified_input:
        confirmed, capsule = VerificationOracle.run_reproof_loop(item)
        status = "verified" if confirmed else "unverified"
        
        updated_item = {
            **item,
            "verification_status": status,
            "proof_capsule": capsule
        }
        final_verified.append(updated_item)
        
        if confirmed:
            # Index into memory for future scans
            ExploitMemoryRAG.index_exploit_memory(
                technology_stack=state.get("target_url", "general"),
                vulnerability_class=item.get("title", "Unknown"),
                attack_strategy_summary=f"3/3 Reproof confirmed on {item.get('url')}",
                successful_payload=str(capsule)
            )
            
        log.append({
            "step": "validator",
            "finding": item.get("title"),
            "status": status,
            "reproof": f"{capsule['reproof_passes_succeeded']}/3"
        })
        cost += 0.015
        
    return {
        "verified_vulnerabilities": final_verified,
        "current_cost": cost,
        "engagement_log": log,
        "flow_status": "validation_completed"
    }
