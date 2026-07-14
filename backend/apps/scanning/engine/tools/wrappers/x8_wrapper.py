"""x8 — Hidden HTTP parameter discovery tool."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class X8Tool(ExternalTool):
    name = 'x8'
    binary = 'x8'
    capabilities = [ToolCapability.WEB_FUZZ, ToolCapability.RECON]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Discover hidden HTTP parameters in a URL.

        target: Target URL (may include a placeholder like ?FUZZ=1)
        options:
          wordlist (str): wordlist path (default built-in)
          method (str): HTTP method 'GET'|'POST' (default 'GET')
          data (str): POST body template (use FUZZ as placeholder)
          headers (dict): extra request headers
          threads (int): number of threads (default 8)
          output_format (str): 'json' (default) or 'text'
        """
        if not self.is_available():
            return []
        args = [
            self.binary,
            '-u', target,
            '-o', options.get('output_format', 'json'),
        ]
        wordlist = options.get('wordlist')
        if wordlist:
            args += ['-w', wordlist]
        method = options.get('method', 'GET')
        args += ['-X', method]
        data = options.get('data')
        if data:
            args += ['-b', data]
        headers = options.get('headers', {})
        for k, v in headers.items():
            args += ['-H', f'{k}: {v}']
        threads = options.get('threads', 8)
        args += ['-t', str(threads)]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        # Try JSON array output
        try:
            data = json.loads(raw)
            items = data if isinstance(data, list) else data.get('results', [data])
            for item in items:
                param = item.get('name', item.get('param', ''))
                reason = item.get('reason', '')
                if not param:
                    continue
                results.append(ToolResult(
                    tool_name=self.name,
                    category='hidden-parameter',
                    title=f'Hidden parameter: {param}',
                    host='',
                    severity=ToolSeverity.MEDIUM,
                    confidence=0.80,
                    metadata={'parameter': param, 'reason': reason},
                ))
        except (json.JSONDecodeError, TypeError):
            # Plain-text fallback: one param per line
            for line in raw.splitlines():
                param = line.strip()
                if param and not param.startswith('['):
                    results.append(ToolResult(
                        tool_name=self.name,
                        category='hidden-parameter',
                        title=f'Hidden parameter: {param}',
                        host='',
                        severity=ToolSeverity.MEDIUM,
                        confidence=0.70,
                        metadata={'parameter': param},
                    ))
        return results


TOOL_CLASS = X8Tool
