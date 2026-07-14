"""RustScan — Ultra fast port scanner as nmap pre-scanner."""
from __future__ import annotations
import re
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class RustscanTool(ExternalTool):
    name = 'rustscan'
    binary = 'rustscan'
    capabilities = [ToolCapability.PORT_SCAN, ToolCapability.NETWORK]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-a', target, '--ulimit', '5000', '-g', '--']
        if options.get('range'):
            args += ['-r', options['range']]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        port_re = re.compile(r'(\d+)\s*->\s*Open', re.IGNORECASE)
        for m in port_re.finditer(raw):
            port = int(m.group(1))
            results.append(ToolResult(
                tool_name=self.name, category='port',
                title=f'Open port: {port}',
                port=port, severity=ToolSeverity.INFO, confidence=0.90,
            ))
        # Fallback: plain list of ports
        if not results:
            for line in raw.strip().splitlines():
                ports = re.findall(r'\b(\d{1,5})\b', line)
                for p in ports:
                    pint = int(p)
                    if 1 <= pint <= 65535:
                        results.append(ToolResult(
                            tool_name=self.name, category='port',
                            title=f'Open port: {pint}',
                            port=pint, severity=ToolSeverity.INFO, confidence=0.85,
                        ))
        return results

TOOL_CLASS = RustscanTool
