"""waybackurls — Fetch URLs from the Wayback Machine."""
from __future__ import annotations
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class WaybackurlsTool(ExternalTool):
    name = 'waybackurls'
    binary = 'waybackurls'
    capabilities = [ToolCapability.RECON, ToolCapability.OSINT]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, target]
        if options.get('no_subs'):
            args.append('-no-subs')
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
                    title=f'Archived: {url[:120]}',
                    url=url, severity=ToolSeverity.INFO, confidence=0.65,
                ))
        return results

TOOL_CLASS = WaybackurlsTool
