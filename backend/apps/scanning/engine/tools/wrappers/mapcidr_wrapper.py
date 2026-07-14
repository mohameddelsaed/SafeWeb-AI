"""Mapcidr — CIDR manipulation and IP range expansion by ProjectDiscovery."""
from __future__ import annotations

from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class MapcidrTool(ExternalTool):
    name = 'mapcidr'
    binary = 'mapcidr'
    capabilities = [ToolCapability.RECON, ToolCapability.NETWORK]
    default_timeout = 60

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Expand/aggregate CIDR ranges.

        target: a CIDR string like '192.168.1.0/24' or comma-separated list.
        options:
          aggregate (bool): aggregate ranges instead of expanding
          count (bool):     just count IPs, don't enumerate
        """
        if not self.is_available():
            return []
        cidrs = [c.strip() for c in target.split(',') if c.strip()]
        if not cidrs:
            return []

        if options.get('aggregate', False):
            args = [self.binary, '-silent', '-aggregate']
        elif options.get('count', False):
            args = [self.binary, '-silent', '-count']
        else:
            # Default: expand single CIDR to IPs
            args = [self.binary, '-silent']

        # Pass CIDRs via -cidr flag
        for cidr in cidrs:
            args += ['-cidr', cidr]

        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            ip = line.strip()
            if not ip:
                continue
            results.append(ToolResult(
                tool_name=self.name,
                category='ip-range',
                title=f'IP: {ip}',
                host=ip,
                severity=ToolSeverity.INFO,
                confidence=1.0,
                metadata={'type': 'expanded_ip'},
            ))
        return results


TOOL_CLASS = MapcidrTool
