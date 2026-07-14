"""Dirsearch — Web path discovery / directory brute-forcer."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class DirsearchTool(ExternalTool):
    name = 'dirsearch'
    binary = 'dirsearch'
    capabilities = [ToolCapability.WEB_FUZZ, ToolCapability.CRAWLER]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '--format=json', '-q']
        if options.get('wordlist'):
            args += ['-w', options['wordlist']]
        if options.get('extensions'):
            args += ['-e', options['extensions']]
        if options.get('threads'):
            args += ['-t', str(options['threads'])]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return results
        items = data.get('results', data) if isinstance(data, dict) else data
        if isinstance(items, list):
            for item in items:
                path = item.get('path', item.get('url', ''))
                status = item.get('status', 0)
                size = item.get('content-length', item.get('size', 0))
                results.append(ToolResult(
                    tool_name=self.name, category='discovery',
                    title=f'{path} (HTTP {status})',
                    url=path, severity=ToolSeverity.INFO, confidence=0.70,
                    metadata={'status': status, 'size': size},
                ))
        return results

TOOL_CLASS = DirsearchTool
