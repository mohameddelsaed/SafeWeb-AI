import logging
from typing import Any, Dict, List
from .result import ToolResult

logger = logging.getLogger(__name__)

class MCPToolServer:
    """Model Context Protocol (MCP) JSON-RPC wrapper for external tools."""
    
    @staticmethod
    def format_json_rpc_response(tool_name: str, target: str, results: List[ToolResult], request_id: Any = 1) -> Dict[str, Any]:
        """Format tool results according to MCP JSON-RPC 2.0 specification."""
        formatted_findings = []
        for r in results:
            formatted_findings.append({
                "title": r.title,
                "severity": r.severity,
                "description": r.description,
                "evidence": r.evidence,
                "url": r.url or target,
                "metadata": r.metadata or {}
            })
            
        return {
            "jsonrpc": "2.0",
            "result": {
                "tool": tool_name,
                "target": target,
                "findings_count": len(formatted_findings),
                "findings": formatted_findings
            },
            "id": request_id
        }

    @staticmethod
    def format_json_rpc_error(code: int, message: str, request_id: Any = 1) -> Dict[str, Any]:
        """Format errors according to MCP JSON-RPC 2.0 specification."""
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            },
            "id": request_id
        }
