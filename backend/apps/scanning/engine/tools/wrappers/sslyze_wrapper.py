"""SSLyze — SSL/TLS configuration analysis."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class SslyzeTool(ExternalTool):
    name = 'sslyze'
    binary = 'sslyze'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.RECON]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, target, '--json_out=-']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return results
        for server in data.get('server_scan_results', []):
            cmds = server.get('scan_commands_results', {})
            # Heartbleed
            hb = cmds.get('heartbleed', {})
            if hb.get('is_vulnerable_to_heartbleed'):
                results.append(ToolResult(
                    tool_name=self.name, category='tls',
                    title='Heartbleed vulnerability', severity=ToolSeverity.CRITICAL,
                    confidence=0.95, cwe='CWE-126',
                ))
            # OpenSSL CCS
            ccs = cmds.get('openssl_ccs_injection', {})
            if ccs.get('is_vulnerable_to_ccs_injection'):
                results.append(ToolResult(
                    tool_name=self.name, category='tls',
                    title='OpenSSL CCS Injection', severity=ToolSeverity.HIGH,
                    confidence=0.95, cwe='CWE-326',
                ))
            # Weak ciphers check
            for proto in ('ssl_2_0', 'ssl_3_0'):
                suite = cmds.get(f'{proto}_cipher_suites', {})
                accepted = suite.get('accepted_cipher_suites', [])
                if accepted:
                    results.append(ToolResult(
                        tool_name=self.name, category='tls',
                        title=f'{proto.upper()} enabled ({len(accepted)} ciphers)',
                        severity=ToolSeverity.HIGH, confidence=0.90,
                        cwe='CWE-326',
                    ))
        return results

TOOL_CLASS = SslyzeTool
