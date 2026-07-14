"""Chaos — ProjectDiscovery's passive subdomain discovery via their dataset API."""
from __future__ import annotations

import os
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class ChaosTool(ExternalTool):
    name = 'chaos'
    binary = 'chaos'
    capabilities = [ToolCapability.SUBDOMAIN, ToolCapability.RECON]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        api_key = options.get('api_key') or os.environ.get('PDCP_API_KEY', '')
        args = [self.binary, '-d', target, '-silent']
        if api_key:
            args += ['-key', api_key]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            host = line.strip().lower()
            if not host or '.' not in host or host in seen:
                continue
            if ' ' in host or host.startswith('['):
                continue
            seen.add(host)
            results.append(ToolResult(
                tool_name=self.name,
                category='subdomain',
                title=f'Subdomain: {host}',
                host=host,
                severity=ToolSeverity.INFO,
                confidence=0.90,
                metadata={'source': 'chaos-dataset'},
            ))
        return results


TOOL_CLASS = ChaosTool
