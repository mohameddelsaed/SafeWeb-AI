"""Tplmap — Server-Side Template Injection (SSTI) detection and exploitation."""
from __future__ import annotations

import re
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_VULN_PATTERNS = [
    r'(Jinja2|Mako|Smarty|Twig|Nunjucks|Pebble|Velocity|FreeMarker|Tornado)\s+\(SSTI\)',
    r'template\s+injection\s+(found|confirmed|detected)',
    r'engine[:\s]+(\S+)\s+\(injectable\)',
]


class TplmapTool(ExternalTool):
    name = 'tplmap'
    binary = 'tplmap'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.EXPLOIT]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Detect Server-Side Template Injection in target URL.

        options:
          level (int): detection level 1-5 (default 5)
          data (str): POST data string
          os_cmd (str): OS command to verify injection (default 'id')
        """
        if not self.is_available():
            return []
        os_cmd = options.get('os_cmd', 'id')
        args = [
            self.binary,
            '-u', target,
            '--os-cmd', os_cmd,
            '--level', str(options.get('level', 5)),
        ]
        data = options.get('data')
        if data:
            args += ['-d', data]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        engine_found: set[str] = set()
        for line in raw.splitlines():
            for pattern in _VULN_PATTERNS:
                m = re.search(pattern, line, re.I)
                if m:
                    engine = m.group(1) if m.lastindex else 'unknown template engine'
                    if engine not in engine_found:
                        engine_found.add(engine)
                        results.append(ToolResult(
                            tool_name=self.name,
                            category='ssti',
                            title=f'SSTI via {engine} template engine',
                            host='',
                            severity=ToolSeverity.CRITICAL,
                            confidence=0.90,
                            metadata={'engine': engine, 'raw_line': line},
                        ))
        return results


TOOL_CLASS = TplmapTool
