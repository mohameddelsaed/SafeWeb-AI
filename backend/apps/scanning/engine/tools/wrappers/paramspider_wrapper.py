"""ParamSpider — Parameter mining from web archives."""
from __future__ import annotations
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class ParamSpiderTool(ExternalTool):
    name = 'paramspider'
    binary = 'paramspider'
    capabilities = [ToolCapability.RECON, ToolCapability.WEB_FUZZ]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-d', target]
        if options.get('exclude'):
            args += ['--exclude', options['exclude']]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen = set()
        for line in raw.strip().splitlines():
            url = line.strip()
            if url.startswith('http') and '=' in url and url not in seen:
                seen.add(url)
                results.append(ToolResult(
                    tool_name=self.name, category='parameter',
                    title=f'Parameterized URL: {url[:120]}',
                    url=url, severity=ToolSeverity.INFO, confidence=0.65,
                ))
        return results

TOOL_CLASS = ParamSpiderTool
