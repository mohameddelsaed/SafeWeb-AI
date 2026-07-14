"""Ghauri — Advanced SQL Injection detection and exploitation tool."""
from __future__ import annotations

import re
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_VULN_PATTERNS = [
    r'parameter\s+["\']?(\S+?)["\']?\s+is\s+(boolean-based|time-based|error-based|stacked|UNION)',
    r'(UNION|boolean|time-based|error-based|stacked\s+queries)\s+blind',
    r'sql\s+injection\s+(found|confirmed)',
]


class GhauriTool(ExternalTool):
    name = 'ghauri'
    binary = 'ghauri'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.EXPLOIT]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Detect SQL injection in target URL.

        options:
          level (int): detection level 1-5 (default 3)
          data (str): POST data string
          cookie (str): cookie header string
          dbs (bool): enumerate databases (default True)
        """
        if not self.is_available():
            return []
        args = [
            self.binary,
            '-u', target,
            '--batch',
            '--flush-session',
            '--level', str(options.get('level', 3)),
        ]
        data = options.get('data')
        if data:
            args += ['--data', data]
        cookie = options.get('cookie')
        if cookie:
            args += ['--cookie', cookie]
        if options.get('dbs', True):
            args.append('--dbs')
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        found_params: set[str] = set()
        for line in raw.splitlines():
            for pattern in _VULN_PATTERNS:
                m = re.search(pattern, line, re.I)
                if m:
                    param = m.group(1) if m.lastindex and m.lastindex >= 1 else 'unknown'
                    injection_type = m.group(2) if m.lastindex and m.lastindex >= 2 else 'unknown'
                    key = f'{param}:{injection_type}'
                    if key not in found_params:
                        found_params.add(key)
                        results.append(ToolResult(
                            tool_name=self.name,
                            category='sqli',
                            title=f'SQL injection ({injection_type}) in parameter "{param}"',
                            host='',
                            severity=ToolSeverity.CRITICAL,
                            confidence=0.90,
                            metadata={
                                'parameter': param,
                                'injection_type': injection_type,
                                'raw_line': line,
                            },
                        ))
        return results


TOOL_CLASS = GhauriTool
