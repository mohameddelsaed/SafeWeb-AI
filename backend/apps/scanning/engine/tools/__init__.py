"""
External Tool Integration Framework.

Provides a unified interface for wrapping 61 external security tools
(nmap, subfinder, nuclei, sqlmap, ffuf, etc.) with consistent result
models, health checks, timeout management, and graceful degradation.
"""
from .base import ExternalTool, ToolCapability
from .result import ToolResult, ToolSeverity
from .registry import ToolRegistry

__all__ = [
    'ExternalTool',
    'ToolCapability',
    'ToolResult',
    'ToolSeverity',
    'ToolRegistry',
]
