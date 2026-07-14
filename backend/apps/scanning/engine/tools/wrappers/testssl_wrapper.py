"""testssl.sh — TLS/SSL cipher and vulnerability testing."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_VULN_SEV = {
    'CRITICAL': ToolSeverity.CRITICAL,
    'HIGH': ToolSeverity.HIGH,
    'MEDIUM': ToolSeverity.MEDIUM,
    'LOW': ToolSeverity.LOW,
    'OK': ToolSeverity.INFO,
    'INFO': ToolSeverity.INFO,
}


class TestsslTool(ExternalTool):
    name = 'testssl'
    binary = 'testssl.sh'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.RECON]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '--jsonfile=/dev/stdout', '--fast', target]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        try:
            data = json.loads(raw)
            findings = data if isinstance(data, list) else data.get('scanResult', [{}])[0].get('findings', [])
        except (json.JSONDecodeError, IndexError, KeyError):
            findings = []
        for f in findings:
            sev_str = f.get('severity', 'INFO').upper()
            sev = _VULN_SEV.get(sev_str, ToolSeverity.INFO)
            if sev == ToolSeverity.INFO and sev_str == 'OK':
                continue  # skip OK findings
            results.append(ToolResult(
                tool_name=self.name, category='tls',
                title=f.get('id', 'Unknown'),
                description=f.get('finding', ''),
                severity=sev, confidence=0.85,
                metadata={'id': f.get('id'), 'cve': f.get('cve', '')},
                cwe='CWE-326' if sev in (ToolSeverity.HIGH, ToolSeverity.CRITICAL) else '',
            ))
        return results

TOOL_CLASS = TestsslTool
