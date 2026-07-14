"""Amass — In-depth attack surface mapping and asset discovery."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class AmassTool(ExternalTool):
    name = 'amass'
    binary = 'amass'
    capabilities = [ToolCapability.SUBDOMAIN, ToolCapability.RECON, ToolCapability.OSINT]
    default_timeout = 600

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        mode = options.get('mode', 'enum')
        args = [self.binary, mode, '-d', target, '-json', '/dev/stdout', '-silent']
        if options.get('passive'):
            args.append('-passive')
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen = set()
        for line in raw.strip().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                if '.' in line and line.strip() not in seen:
                    seen.add(line.strip())
                    results.append(ToolResult(
                        tool_name=self.name, category='subdomain',
                        title=f'Subdomain: {line.strip()}', host=line.strip(),
                        severity=ToolSeverity.INFO, confidence=0.80,
                    ))
                continue
            name = obj.get('name', '')
            if name and name not in seen:
                seen.add(name)
                results.append(ToolResult(
                    tool_name=self.name, category='subdomain',
                    title=f'Subdomain: {name}', host=name,
                    severity=ToolSeverity.INFO, confidence=0.85,
                    metadata={
                        'addresses': obj.get('addresses', []),
                        'sources': obj.get('sources', []),
                        'tag': obj.get('tag', ''),
                    },
                ))
        return results

TOOL_CLASS = AmassTool
