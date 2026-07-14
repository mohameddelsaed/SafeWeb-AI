"""httpx — HTTP toolkit for probing, tech detection, status codes."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class HttpxTool(ExternalTool):
    name = 'httpx'
    binary = 'httpx'
    capabilities = [ToolCapability.RECON, ToolCapability.CRAWLER]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '-json', '-silent',
                '-status-code', '-title', '-tech-detect', '-follow-redirects']
        if options.get('threads'):
            args += ['-threads', str(options['threads'])]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get('url', '')
            status = obj.get('status_code', obj.get('status-code', 0))
            title = obj.get('title', '')
            tech = obj.get('tech', [])
            results.append(ToolResult(
                tool_name=self.name, category='probe',
                title=f'HTTP {status}: {title[:60]}',
                url=url, severity=ToolSeverity.INFO, confidence=0.90,
                metadata={
                    'status': status, 'title': title,
                    'tech': tech,
                    'content_length': obj.get('content_length', 0),
                    'webserver': obj.get('webserver', ''),
                    'cdn': obj.get('cdn', False),
                },
            ))
        return results

TOOL_CLASS = HttpxTool
