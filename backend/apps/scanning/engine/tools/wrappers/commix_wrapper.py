"""Commix — Automated OS command injection exploitation."""
from __future__ import annotations
import re
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class CommixTool(ExternalTool):
    name = 'commix'
    binary = 'commix'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.EXPLOIT]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '--batch']
        if options.get('data'):
            args += ['--data', options['data']]
        if options.get('cookie'):
            args += ['--cookie', options['cookie']]
        if options.get('level'):
            args += ['--level', str(options['level'])]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        vuln_re = re.compile(
            r'The\s+(\w+)\s+parameter.*?is\s+vulnerable.*?technique:\s*(\w+)',
            re.I | re.DOTALL,
        )
        for m in vuln_re.finditer(raw):
            param, technique = m.groups()
            results.append(ToolResult(
                tool_name=self.name, category='cmdi',
                title=f'Command Injection in: {param}',
                description=f'Technique: {technique}',
                severity=ToolSeverity.CRITICAL, confidence=0.90,
                evidence=raw[max(0, m.start()-100):m.end()+200][:500],
                cwe='CWE-78',
                metadata={'parameter': param, 'technique': technique},
            ))
        if not results and 'is vulnerable' in raw.lower():
            results.append(ToolResult(
                tool_name=self.name, category='cmdi',
                title='Command Injection detected',
                severity=ToolSeverity.CRITICAL, confidence=0.85,
                evidence=raw[:500], cwe='CWE-78',
            ))
        return results

TOOL_CLASS = CommixTool
