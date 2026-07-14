"""qsreplace — Replace query string values in URLs."""
from __future__ import annotations
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class QsreplaceTool(ExternalTool):
    name = 'qsreplace'
    binary = 'qsreplace'
    capabilities = [ToolCapability.WEB_FUZZ]
    default_timeout = 60

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        payload = options.get('payload', 'FUZZ')
        args = [self.binary, payload]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            url = line.strip()
            if url:
                results.append(ToolResult(
                    tool_name=self.name, category='url_mutation',
                    title=f'Fuzzed: {url[:120]}',
                    url=url, severity=ToolSeverity.INFO, confidence=0.50,
                ))
        return results

TOOL_CLASS = QsreplaceTool
