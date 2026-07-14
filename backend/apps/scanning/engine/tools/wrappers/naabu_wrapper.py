"""Naabu — Fast port scanner by ProjectDiscovery."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

# Ports with high exploitation potential — flag as medium
_SENSITIVE_PORTS = {
    21, 22, 23, 25, 110, 135, 139, 445, 1433, 1521, 2375, 2376,
    3306, 3389, 5432, 5900, 6379, 9200, 27017, 6443, 2379, 11211,
}


class NaabuTool(ExternalTool):
    name = 'naabu'
    binary = 'naabu'
    capabilities = [ToolCapability.PORT_SCAN, ToolCapability.NETWORK]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Fast SYN/CONNECT port scan.

        options:
          top_ports (int|str): number of top ports or 'full' (default 1000)
          ports (str): comma-separated port list (overrides top_ports)
          rate (int): packets-per-second rate (default 1000)
          exclude_ports (str): comma-separated ports to exclude
        """
        if not self.is_available():
            return []
        args = [self.binary, '-host', target, '-json', '-silent', '-no-color']

        ports = options.get('ports')
        top_ports = options.get('top_ports', 1000)
        if ports:
            args += ['-p', str(ports)]
        elif top_ports == 'full':
            args += ['-p', '-']  # all 65535
        else:
            args += ['-top-ports', str(top_ports)]

        rate = options.get('rate', 1000)
        args += ['-rate', str(rate)]

        exclude = options.get('exclude_ports')
        if exclude:
            args += ['-exclude-ports', exclude]

        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get('ip', obj.get('host', ''))
            port = int(obj.get('port', 0))
            protocol = obj.get('protocol', 'tcp')
            if not port:
                continue
            sev = ToolSeverity.MEDIUM if port in _SENSITIVE_PORTS else ToolSeverity.INFO
            results.append(ToolResult(
                tool_name=self.name,
                category='open-port',
                title=f'Open port: {host}:{port}/{protocol}',
                host=host,
                port=port,
                severity=sev,
                confidence=0.95,
                metadata={'protocol': protocol},
            ))
        return results


TOOL_CLASS = NaabuTool
