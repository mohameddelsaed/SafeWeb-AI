"""MassDNS — High-performance DNS resolution."""
from __future__ import annotations
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class MassdnsTool(ExternalTool):
    name = 'massdns'
    binary = 'massdns'
    capabilities = [ToolCapability.DNS, ToolCapability.SUBDOMAIN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        resolvers = options.get('resolvers', '/usr/share/massdns/resolvers.txt')
        args = [self.binary, '-r', resolvers, '-t', 'A', '-o', 'S', '-q', target]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen = set()
        for line in raw.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                name = parts[0].rstrip('.')
                rtype = parts[1]
                value = parts[2]
                if name not in seen:
                    seen.add(name)
                    results.append(ToolResult(
                        tool_name=self.name, category='dns',
                        title=f'{rtype}: {name} → {value}',
                        host=name, severity=ToolSeverity.INFO, confidence=0.80,
                        metadata={'type': rtype, 'value': value},
                    ))
        return results

TOOL_CLASS = MassdnsTool
