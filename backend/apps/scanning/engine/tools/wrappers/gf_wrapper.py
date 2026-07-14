"""gf — Pattern grep wrapper for extracting interesting parameters."""
from __future__ import annotations
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class GfTool(ExternalTool):
    name = 'gf'
    binary = 'gf'
    capabilities = [ToolCapability.RECON, ToolCapability.WEB_FUZZ]
    default_timeout = 60

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """target should be a file path or piped input with URLs."""
        if not self.is_available():
            return []
        pattern = options.get('pattern', 'xss')  # xss, sqli, ssrf, redirect, etc.
        args = [self.binary, pattern]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen = set()
        for line in raw.strip().splitlines():
            url = line.strip()
            if url and url not in seen:
                seen.add(url)
                results.append(ToolResult(
                    tool_name=self.name, category='parameter',
                    title=f'Interesting param: {url[:120]}',
                    url=url, severity=ToolSeverity.LOW, confidence=0.60,
                ))
        return results

TOOL_CLASS = GfTool
