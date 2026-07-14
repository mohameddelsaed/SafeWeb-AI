"""Masscan — Internet-scale port scanner."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_SENSITIVE_PORTS = {
    21, 22, 23, 25, 110, 135, 139, 445, 1433, 1521, 2375, 2376,
    3306, 3389, 5432, 5900, 6379, 9200, 27017, 6443, 2379, 11211,
}


class MasscanTool(ExternalTool):
    name = 'masscan'
    binary = 'masscan'
    capabilities = [ToolCapability.PORT_SCAN, ToolCapability.NETWORK]
    default_timeout = 600

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Fast port scan using masscan.

        target: IP address, CIDR range, or hostname
        options:
          ports (str): port range or list — e.g. '80,443,1-1024' (default top 100 ports)
          rate (int): packets per second — default 1000 (keep low without sudo)
          banners (bool): capture banners (default False — requires root)
        """
        if not self.is_available():
            return []
        ports = options.get('ports', '21,22,23,25,53,80,110,139,143,443,445,993,995,'
                                     '1433,1521,2375,3306,3389,5432,5900,6379,8080,8443,'
                                     '8888,9200,11211,27017')
        rate = options.get('rate', 1000)
        args = [
            self.binary,
            target,
            '-p', ports,
            '--rate', str(rate),
            '-oJ', '-',  # JSON to stdout
        ]
        if options.get('banners', False):
            args.append('--banners')
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        seen: set[tuple] = set()
        # masscan -oJ outputs a JSON array with leading/trailing lines
        # Strip non-JSON lines and parse
        cleaned_lines = []
        for line in raw.splitlines():
            line = line.strip()
            if line in (',', '[', ']', ''):
                continue
            line = line.rstrip(',')
            cleaned_lines.append(line)
        for line in cleaned_lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = obj.get('ip', '')
            for pobj in obj.get('ports', []):
                port = int(pobj.get('port', 0))
                protocol = pobj.get('proto', 'tcp')
                status = pobj.get('status', 'open')
                if status != 'open' or not port:
                    continue
                key = (ip, port, protocol)
                if key in seen:
                    continue
                seen.add(key)
                sev = ToolSeverity.MEDIUM if port in _SENSITIVE_PORTS else ToolSeverity.INFO
                banner = pobj.get('service', {}).get('banner', '')
                results.append(ToolResult(
                    tool_name=self.name,
                    category='open-port',
                    title=f'Open port: {ip}:{port}/{protocol}',
                    host=ip,
                    port=port,
                    severity=sev,
                    confidence=0.95,
                    metadata={'protocol': protocol, 'banner': banner},
                ))
        return results


TOOL_CLASS = MasscanTool
