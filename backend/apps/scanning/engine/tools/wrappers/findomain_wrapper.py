"""Findomain — Fast cross-platform subdomain enumerator."""
from __future__ import annotations

from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class FindomainTool(ExternalTool):
    name = 'findomain'
    binary = 'findomain'
    capabilities = [ToolCapability.SUBDOMAIN, ToolCapability.RECON]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        # -t: target domain, -q: quiet mode (results only)
        args = [self.binary, '-t', target, '-q']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            host = line.strip().lower()
            if not host or '.' not in host or host in seen:
                continue
            if ' ' in host or host.startswith('[') or host.startswith('http'):
                continue
            seen.add(host)
            results.append(ToolResult(
                tool_name=self.name,
                category='subdomain',
                title=f'Subdomain: {host}',
                host=host,
                severity=ToolSeverity.INFO,
                confidence=0.82,
                metadata={'source': 'findomain'},
            ))
        return results


TOOL_CLASS = FindomainTool
