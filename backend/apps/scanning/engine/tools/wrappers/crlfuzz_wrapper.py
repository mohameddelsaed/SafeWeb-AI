"""CRLFuzz — CRLF injection scanner."""
from __future__ import annotations
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class CrlfuzzTool(ExternalTool):
    name = 'crlfuzz'
    binary = 'crlfuzz'
    capabilities = [ToolCapability.VULN_SCAN]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '-s']
        if options.get('concurrency'):
            args += ['-c', str(options['concurrency'])]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            url = line.strip()
            if url and url.startswith('http'):
                results.append(ToolResult(
                    tool_name=self.name, category='crlf',
                    title=f'CRLF Injection: {url[:120]}',
                    url=url, severity=ToolSeverity.MEDIUM, confidence=0.80,
                    cwe='CWE-93',
                ))
        return results

TOOL_CLASS = CrlfuzzTool
