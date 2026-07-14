"""Dalfox — XSS scanner with parameter analysis and DOM-based detection."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class DalfoxTool(ExternalTool):
    name = 'dalfox'
    binary = 'dalfox'
    capabilities = [ToolCapability.VULN_SCAN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, 'url', target, '--format', 'json', '--silence']
        if options.get('cookie'):
            args += ['--cookie', options['cookie']]
        if options.get('headers'):
            for k, v in options['headers'].items():
                args += ['--header', f'{k}: {v}']
        if options.get('blind'):
            args += ['--blind', options['blind']]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            poc_type = obj.get('type', 'xss')
            param = obj.get('param', '')
            payload = obj.get('payload', '')
            poc_url = obj.get('proof_of_concept', obj.get('poc', ''))
            sev = ToolSeverity.HIGH if 'dom' in poc_type.lower() else ToolSeverity.MEDIUM
            results.append(ToolResult(
                tool_name=self.name, category='xss',
                title=f'XSS ({poc_type}) in param: {param}',
                description=f'Payload: {payload[:200]}',
                severity=sev, confidence=0.85,
                url=poc_url, evidence=payload[:500],
                cwe='CWE-79',
                metadata={'type': poc_type, 'param': param, 'payload': payload},
            ))
        return results

TOOL_CLASS = DalfoxTool
