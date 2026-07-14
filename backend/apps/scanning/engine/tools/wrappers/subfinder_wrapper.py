"""Subfinder — Passive subdomain discovery tool."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class SubfinderTool(ExternalTool):
    name = 'subfinder'
    binary = 'subfinder'
    capabilities = [ToolCapability.SUBDOMAIN, ToolCapability.RECON]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-d', target, '-silent', '-json']
        if options.get('sources'):
            args += ['-sources', ','.join(options['sources'])]
        if options.get('recursive'):
            args += ['-recursive']
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
                host = obj.get('host', line)
                source = obj.get('source', 'unknown')
            except json.JSONDecodeError:
                host = line
                source = 'unknown'
            if not host or '.' not in host:
                continue
            results.append(ToolResult(
                tool_name=self.name,
                category='subdomain',
                title=f'Subdomain: {host}',
                host=host,
                severity=ToolSeverity.INFO,
                confidence=0.85,
                metadata={'source': source},
            ))
        return results


TOOL_CLASS = SubfinderTool
