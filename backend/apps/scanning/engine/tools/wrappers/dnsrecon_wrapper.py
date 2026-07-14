"""DNSRecon — DNS enumeration and zone transfer testing."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class DnsreconTool(ExternalTool):
    name = 'dnsrecon'
    binary = 'dnsrecon'
    capabilities = [ToolCapability.DNS, ToolCapability.RECON]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-d', target, '-j', '/dev/stdout']
        scan_type = options.get('type', 'std')
        args += ['-t', scan_type]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return results
        records = data if isinstance(data, list) else data.get('records', [])
        for rec in records:
            rtype = rec.get('type', '')
            name = rec.get('name', '')
            addr = rec.get('address', rec.get('target', ''))
            if rtype == 'info' and 'zone transfer' in rec.get('zone_transfer', '').lower():
                results.append(ToolResult(
                    tool_name=self.name, category='dns',
                    title=f'Zone Transfer possible for {name}',
                    severity=ToolSeverity.HIGH, confidence=0.95,
                    cwe='CWE-200',
                ))
            else:
                results.append(ToolResult(
                    tool_name=self.name, category='dns',
                    title=f'{rtype}: {name} → {addr}',
                    severity=ToolSeverity.INFO, confidence=0.85,
                    metadata={'type': rtype, 'name': name, 'address': addr},
                ))
        return results

TOOL_CLASS = DnsreconTool
