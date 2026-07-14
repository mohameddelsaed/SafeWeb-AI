"""Sublist3r — Passive subdomain enumeration using multiple search engines."""
from __future__ import annotations

from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class Sublist3rTool(ExternalTool):
    name = 'sublist3r'
    binary = 'sublist3r'
    capabilities = [ToolCapability.SUBDOMAIN, ToolCapability.RECON]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        # -d: domain, -o -: write results to stdout (pipe-friendly)
        # -n: no color output
        args = [self.binary, '-d', target, '-n', '-o', '-']
        threads = options.get('threads', 40)
        args += ['-t', str(threads)]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            host = line.strip().lower()
            # Skip banner/info lines
            if not host or '.' not in host or host in seen:
                continue
            if any(c in host for c in (' ', '[', ']', '|')):
                continue
            if host.startswith('http'):
                continue
            seen.add(host)
            results.append(ToolResult(
                tool_name=self.name,
                category='subdomain',
                title=f'Subdomain: {host}',
                host=host,
                severity=ToolSeverity.INFO,
                confidence=0.78,
                metadata={'source': 'sublist3r'},
            ))
        return results


TOOL_CLASS = Sublist3rTool
