"""Assetfinder — Passive subdomain discovery via multiple passive sources."""
from __future__ import annotations

from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class AssetfinderTool(ExternalTool):
    name = 'assetfinder'
    binary = 'assetfinder'
    capabilities = [ToolCapability.SUBDOMAIN, ToolCapability.RECON]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        # --subs-only: suppress parent domain, return only subdomains
        args = [self.binary, '--subs-only', target]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            host = line.strip().lower()
            if not host or '.' not in host or host in seen:
                continue
            # Filter out lines that are error messages
            if ' ' in host or host.startswith('http'):
                continue
            seen.add(host)
            results.append(ToolResult(
                tool_name=self.name,
                category='subdomain',
                title=f'Subdomain: {host}',
                host=host,
                severity=ToolSeverity.INFO,
                confidence=0.80,
                metadata={'source': 'assetfinder'},
            ))
        return results


TOOL_CLASS = AssetfinderTool
