"""GoSpider — Web spider / crawler written in Go."""
from __future__ import annotations
import re
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class GospiderTool(ExternalTool):
    name = 'gospider'
    binary = 'gospider'
    capabilities = [ToolCapability.CRAWLER, ToolCapability.RECON]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-s', target, '-d', str(options.get('depth', 2)),
                '-c', str(options.get('concurrency', 5)), '--json', '-q']
        if options.get('include_subs'):
            args.append('--include-subs')
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen = set()
        for line in raw.strip().splitlines():
            url_match = re.search(r'https?://\S+', line)
            if url_match:
                url = url_match.group()
                if url not in seen:
                    seen.add(url)
                    source = 'form' if '[form]' in line else 'link' if '[href]' in line else 'js' if '[script]' in line else 'other'
                    results.append(ToolResult(
                        tool_name=self.name, category='url_discovery',
                        title=f'[{source}] {url[:120]}',
                        url=url, severity=ToolSeverity.INFO, confidence=0.75,
                        metadata={'source': source},
                    ))
        return results

TOOL_CLASS = GospiderTool
