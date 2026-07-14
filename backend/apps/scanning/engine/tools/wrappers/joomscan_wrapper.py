"""JoomScan — Joomla vulnerability scanner."""
from __future__ import annotations
import re
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class JoomscanTool(ExternalTool):
    name = 'joomscan'
    binary = 'joomscan'
    capabilities = [ToolCapability.VULN_SCAN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-u', target]
        if options.get('enumerate'):
            args += ['-ec']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        ver_match = re.search(r'Joomla\s+(\d[\d.]+)', raw)
        if ver_match:
            results.append(ToolResult(
                tool_name=self.name, category='cms',
                title=f'Joomla version: {ver_match.group(1)}',
                severity=ToolSeverity.INFO, confidence=0.85,
                metadata={'version': ver_match.group(1)},
            ))
        vuln_re = re.compile(r'\[\+\+\]\s*(.*)', re.MULTILINE)
        for m in vuln_re.finditer(raw):
            results.append(ToolResult(
                tool_name=self.name, category='cms',
                title=f'Joomla: {m.group(1)[:100]}',
                severity=ToolSeverity.MEDIUM, confidence=0.70,
            ))
        return results

TOOL_CLASS = JoomscanTool
