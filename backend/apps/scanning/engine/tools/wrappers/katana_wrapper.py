"""Katana — Next-gen crawling and spidering framework (ProjectDiscovery)."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class KatanaTool(ExternalTool):
    name = 'katana'
    binary = 'katana'
    capabilities = [ToolCapability.CRAWLER, ToolCapability.RECON]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '-jsonl', '-silent', '-nc',
                '-d', str(options.get('depth', 3)),
                '-jc',  # JS crawling
                '-kf', 'all']  # known files
        if options.get('headless'):
            args.append('-headless')
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen = set()
        for line in raw.strip().splitlines():
            try:
                obj = json.loads(line)
                url = obj.get('request', {}).get('endpoint', line.strip())
                method = obj.get('request', {}).get('method', 'GET')
                source = obj.get('request', {}).get('source', '')
            except json.JSONDecodeError:
                url = line.strip()
                method, source = 'GET', ''
            if url and url not in seen:
                seen.add(url)
                results.append(ToolResult(
                    tool_name=self.name, category='url_discovery',
                    title=f'[{method}] {url[:120]}',
                    url=url, severity=ToolSeverity.INFO, confidence=0.80,
                    metadata={'method': method, 'source': source},
                ))
        return results

TOOL_CLASS = KatanaTool
