"""
ToolRegistry — Central catalog of all available external tool wrappers.

Supports:
  - Auto-discovery and registration of tool classes
  - Querying tools by capability (recon, vuln_scan, etc.)
  - Health checks across all registered tools
  - Graceful degradation: tools that aren't installed are skipped
"""
from __future__ import annotations

import logging
from typing import Type, Any

from .base import ExternalTool, ToolCapability

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Singleton registry for all external tool wrappers."""

    _instance: 'ToolRegistry | None' = None
    _tools: dict[str, ExternalTool]

    def __new__(cls) -> 'ToolRegistry':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools = {}
        return cls._instance

    # ── Registration ──────────────────────────────────────────────────────

    def register(self, tool_cls: Type[ExternalTool], **kwargs) -> None:
        """Instantiate and register a tool wrapper."""
        tool = tool_cls(**kwargs)
        self._tools[tool.name] = tool
        logger.debug('Registered tool: %s (%s)', tool.name, tool.binary)

    def register_instance(self, tool: ExternalTool) -> None:
        """Register a pre-instantiated tool."""
        self._tools[tool.name] = tool

    # ── Queries ───────────────────────────────────────────────────────────

    def get(self, name: str) -> ExternalTool | None:
        return self._tools.get(name)

    def get_available(self) -> list[ExternalTool]:
        """Return only tools whose binary is installed."""
        return [t for t in self._tools.values() if t.is_available()]

    def get_by_capability(self, cap: ToolCapability) -> list[ExternalTool]:
        """Return available tools that support a given capability."""
        return [
            t for t in self._tools.values()
            if cap in t.capabilities and t.is_available()
        ]

    def all_tools(self) -> list[ExternalTool]:
        return list(self._tools.values())

    def run_tool_mcp(self, name: str, target: str, request_id: Any = 1, **options: Any) -> dict[str, Any]:
        """Run tool by name and return MCP JSON-RPC response."""
        tool = self.get(name)
        if not tool:
            from .mcp_server import MCPToolServer
            return MCPToolServer.format_json_rpc_error(-32601, f"Tool '{name}' not found in registry.", request_id=request_id)
        return tool.run_mcp(target, request_id=request_id, **options)

    # ── Health ────────────────────────────────────────────────────────────

    def health_check(self) -> dict[str, bool]:
        """Return {tool_name: is_available} for every registered tool."""
        return {name: t.is_available() for name, t in self._tools.items()}

    def summary(self) -> str:
        """Human-readable summary of registered tools and availability."""
        lines = []
        for name, tool in sorted(self._tools.items()):
            status = 'OK' if tool.is_available() else 'MISSING'
            caps = ', '.join(c.value for c in tool.capabilities)
            lines.append(f'  {name:20s} [{status:7s}]  caps: {caps}')
        return '\n'.join(lines) or '  (no tools registered)'

    def __len__(self) -> int:
        return len(self._tools)


# ── Module-level convenience ──────────────────────────────────────────────────

_registry = ToolRegistry()


def get_registry() -> ToolRegistry:
    """Return the global ToolRegistry singleton."""
    return _registry


def register_all_tools() -> ToolRegistry:
    """Import and register all known tool wrappers. Call once at startup."""
    from .wrappers import (
        nmap_wrapper,
        subfinder_wrapper,
        nuclei_cli_wrapper,
        sqlmap_wrapper,
        ffuf_wrapper,
        nikto_wrapper,
        whatweb_wrapper,
        wappalyzer_wrapper,
        amass_wrapper,
        httpx_wrapper,
        dirsearch_wrapper,
        gau_wrapper,
        waybackurls_wrapper,
        dalfox_wrapper,
        commix_wrapper,
        arjun_wrapper,
        paramspider_wrapper,
        testssl_wrapper,
        sslyze_wrapper,
        wpscan_wrapper,
        joomscan_wrapper,
        dnsrecon_wrapper,
        massdns_wrapper,
        gospider_wrapper,
        katana_wrapper,
        feroxbuster_wrapper,
        rustscan_wrapper,
        gf_wrapper,
        qsreplace_wrapper,
        crlfuzz_wrapper,
        # Phase A — subdomain / recon
        assetfinder_wrapper,
        findomain_wrapper,
        chaos_wrapper,
        sublist3r_wrapper,
        asnmap_wrapper,
        mapcidr_wrapper,
        dnsx_wrapper,
        puredns_wrapper,
        hakrawler_wrapper,
        getjs_wrapper,
        httprobe_wrapper,
        tlsx_wrapper,
        # Port scan
        naabu_wrapper,
        # Phase B — vuln scanners
        xsstrike_wrapper,
        ghauri_wrapper,
        tplmap_wrapper,
        subjack_wrapper,
        subover_wrapper,
        # Phase C — secrets / links
        trufflehog_wrapper,
        gitleaks_wrapper,
        linkfinder_wrapper,
        secretfinder_wrapper,
        # Phase D — cloud enum
        cloudenum_wrapper,
        s3scanner_wrapper,
        awsbucketdump_wrapper,
        # Phase E — fuzzing / scanning / screenshots
        gobuster_wrapper,
        x8_wrapper,
        masscan_wrapper,
        eyewitness_wrapper,
        aquatone_wrapper,
        # Phase F — OOB
        interactsh_wrapper,
    )
    wrapper_modules = [
        nmap_wrapper, subfinder_wrapper, nuclei_cli_wrapper, sqlmap_wrapper,
        ffuf_wrapper, nikto_wrapper, whatweb_wrapper, wappalyzer_wrapper,
        amass_wrapper, httpx_wrapper, dirsearch_wrapper, gau_wrapper,
        waybackurls_wrapper, dalfox_wrapper, commix_wrapper, arjun_wrapper,
        paramspider_wrapper, testssl_wrapper, sslyze_wrapper, wpscan_wrapper,
        joomscan_wrapper, dnsrecon_wrapper, massdns_wrapper, gospider_wrapper,
        katana_wrapper, feroxbuster_wrapper, rustscan_wrapper, gf_wrapper,
        qsreplace_wrapper, crlfuzz_wrapper,
        # Phase A
        assetfinder_wrapper, findomain_wrapper, chaos_wrapper, sublist3r_wrapper,
        asnmap_wrapper, mapcidr_wrapper, dnsx_wrapper, puredns_wrapper,
        hakrawler_wrapper, getjs_wrapper, httprobe_wrapper, tlsx_wrapper,
        # Port scan
        naabu_wrapper,
        # Phase B
        xsstrike_wrapper, ghauri_wrapper, tplmap_wrapper, subjack_wrapper,
        subover_wrapper,
        # Phase C
        trufflehog_wrapper, gitleaks_wrapper, linkfinder_wrapper, secretfinder_wrapper,
        # Phase D
        cloudenum_wrapper, s3scanner_wrapper, awsbucketdump_wrapper,
        # Phase E
        gobuster_wrapper, x8_wrapper, masscan_wrapper, eyewitness_wrapper,
        aquatone_wrapper,
        # Phase F
        interactsh_wrapper,
    ]
    for mod in wrapper_modules:
        if hasattr(mod, 'TOOL_CLASS'):
            _registry.register(mod.TOOL_CLASS)
    logger.info('Registered %d external tools', len(_registry))
    return _registry
