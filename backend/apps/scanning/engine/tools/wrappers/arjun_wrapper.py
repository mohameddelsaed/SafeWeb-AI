"""Arjun — HTTP parameter discovery."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class ArjunTool(ExternalTool):
    name = 'arjun'
    binary = 'arjun'
    capabilities = [ToolCapability.WEB_FUZZ, ToolCapability.RECON]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '-oJ', '/dev/stdout']
        if options.get('method'):
            args += ['-m', options['method']]
        if options.get('headers'):
            for k, v in options['headers'].items():
                args += ['--headers', f'{k}: {v}']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return results
        for url, params in data.items() if isinstance(data, dict) else []:
            if isinstance(params, list):
                for p in params:
                    results.append(ToolResult(
                        tool_name=self.name, category='parameter',
                        title=f'Hidden param: {p}',
                        url=url, severity=ToolSeverity.LOW, confidence=0.75,
                        metadata={'parameter': p, 'url': url},
                    ))
        return results

TOOL_CLASS = ArjunTool
