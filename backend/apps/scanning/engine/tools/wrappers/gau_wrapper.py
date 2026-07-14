"""gau (GetAllUrls) — Fetch known URLs from AlienVault/Wayback/CommonCrawl."""
from __future__ import annotations
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class GauTool(ExternalTool):
    name = 'gau'
    binary = 'gau'
    capabilities = [ToolCapability.RECON, ToolCapability.OSINT]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, target, '--subs']
        if options.get('providers'):
            args += ['--providers', options['providers']]
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
                    tool_name=self.name, category='url_discovery',
                    title=f'URL: {url[:120]}',
                    url=url, severity=ToolSeverity.INFO, confidence=0.70,
                ))
        return results

TOOL_CLASS = GauTool
