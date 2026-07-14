"""Nuclei CLI — Full Nuclei binary integration for template-based scanning."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_SEV_MAP = {
    'critical': ToolSeverity.CRITICAL,
    'high': ToolSeverity.HIGH,
    'medium': ToolSeverity.MEDIUM,
    'low': ToolSeverity.LOW,
    'info': ToolSeverity.INFO,
}


class NucleiCLITool(ExternalTool):
    name = 'nuclei'
    binary = 'nuclei'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.RECON]
    default_timeout = 600

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '-jsonl', '-silent', '-nc']
        severity = options.get('severity')
        if severity:
            args += ['-severity', severity]
        tags = options.get('tags')
        if tags:
            args += ['-tags', tags]
        templates = options.get('templates')
        if templates:
            args += ['-t', templates]
        templates_dir = options.get('templates_dir')
        if templates_dir:
            args += ['-t', str(templates_dir)]
        rate_limit = options.get('rate_limit', 150)
        args += ['-rl', str(rate_limit)]
        concurrency = options.get('concurrency', 25)
        args += ['-c', str(concurrency)]
        req_timeout = options.get('req_timeout', 10)
        args += ['-timeout', str(req_timeout)]
        if options.get('follow_redirects', False):
            args += ['-fr']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get('info', {})
            sev = _SEV_MAP.get(info.get('severity', 'info'), ToolSeverity.INFO)
            matched = obj.get('matched-at', obj.get('host', ''))
            template_id = obj.get('template-id', obj.get('templateID', ''))
            results.append(ToolResult(
                tool_name=self.name,
                category=info.get('classification', {}).get('cwe-id', ['vuln_scan'])[0]
                         if isinstance(info.get('classification', {}).get('cwe-id'), list)
                         else 'vuln_scan',
                title=f"[{template_id}] {info.get('name', 'Unknown')}",
                description=info.get('description', ''),
                severity=sev,
                confidence=0.85 if sev in (ToolSeverity.HIGH, ToolSeverity.CRITICAL) else 0.70,
                url=matched,
                evidence=obj.get('extracted-results', obj.get('matcher-name', '')),
                cwe=', '.join(info.get('classification', {}).get('cwe-id', [])) if isinstance(info.get('classification', {}).get('cwe-id'), list) else '',
                cvss=float(info.get('classification', {}).get('cvss-score', 0) or 0),
                metadata={
                    'template_id': template_id,
                    'tags': info.get('tags', []),
                    'reference': info.get('reference', []),
                    'matcher_name': obj.get('matcher-name', ''),
                    'curl_command': obj.get('curl-command', ''),
                },
            ))
        return results


TOOL_CLASS = NucleiCLITool
