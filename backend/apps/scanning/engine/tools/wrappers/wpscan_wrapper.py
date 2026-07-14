"""WPScan — WordPress vulnerability scanner."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class WpscanTool(ExternalTool):
    name = 'wpscan'
    binary = 'wpscan'
    capabilities = [ToolCapability.VULN_SCAN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '--url', target, '-f', 'json', '--no-banner']
        if options.get('api_token'):
            args += ['--api-token', options['api_token']]
        if options.get('enumerate'):
            args += ['--enumerate', options['enumerate']]
        else:
            args += ['--enumerate', 'ap,at,tt,cb,dbe,u1-20']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return results
        # WordPress version
        ver = data.get('version', {})
        if ver.get('status') == 'insecure':
            results.append(ToolResult(
                tool_name=self.name, category='cms',
                title=f"Outdated WordPress {ver.get('number', '?')}",
                severity=ToolSeverity.HIGH, confidence=0.90,
                metadata={'version': ver.get('number')},
            ))
        # Plugin/theme vulns
        for section in ('plugins', 'themes'):
            for name, info in data.get(section, {}).items():
                for vuln in info.get('vulnerabilities', []):
                    sev = ToolSeverity.HIGH
                    if 'rce' in vuln.get('title', '').lower():
                        sev = ToolSeverity.CRITICAL
                    results.append(ToolResult(
                        tool_name=self.name, category='cms',
                        title=f"WP {section[:-1]} {name}: {vuln.get('title', '')}",
                        severity=sev, confidence=0.85,
                        cwe=vuln.get('cwe', ''),
                        metadata={
                            'wpvulndb': vuln.get('wpvulndb', ''),
                            'fixed_in': vuln.get('fixed_in', ''),
                            'references': vuln.get('references', {}),
                        },
                    ))
        return results

TOOL_CLASS = WpscanTool
