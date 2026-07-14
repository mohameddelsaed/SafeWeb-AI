"""Nikto — Web server vulnerability scanner."""
from __future__ import annotations
import json
import re
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class NiktoTool(ExternalTool):
    name = 'nikto'
    binary = 'nikto'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.RECON]
    default_timeout = 600

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-h', target, '-Format', 'json', '-nointeractive']
        if options.get('tuning'):
            args += ['-Tuning', options['tuning']]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        try:
            data = json.loads(raw)
            vulns = data if isinstance(data, list) else data.get('vulnerabilities', [])
        except json.JSONDecodeError:
            vulns = []
            for m in re.finditer(r'\+\s+(\S+):\s+(.*)', raw):
                vulns.append({'id': m.group(1), 'msg': m.group(2)})
        for v in vulns:
            msg = v.get('msg', v.get('message', str(v)))
            osvdb = v.get('id', v.get('OSVDB', ''))
            results.append(ToolResult(
                tool_name=self.name,
                category='misconfig',
                title=f'Nikto: {msg[:100]}',
                description=msg,
                severity=ToolSeverity.MEDIUM,
                confidence=0.65,
                metadata={'osvdb': osvdb},
            ))
        return results

TOOL_CLASS = NiktoTool
