"""SQLMap — Automatic SQL injection detection and exploitation."""
from __future__ import annotations

import re
import tempfile
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class SqlmapTool(ExternalTool):
    name = 'sqlmap'
    binary = 'sqlmap'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.EXPLOIT]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        with tempfile.TemporaryDirectory(prefix='sqlmap_') as tmpdir:
            args = [
                self.binary,
                '-u', target,
                '--batch',           # non-interactive
                '--output-dir', tmpdir,
                '--forms' if options.get('forms') else '',
                '--level', str(options.get('level', 2)),
                '--risk', str(options.get('risk', 1)),
            ]
            args = [a for a in args if a]  # remove empties
            if options.get('cookie'):
                args += ['--cookie', options['cookie']]
            if options.get('headers'):
                for k, v in options['headers'].items():
                    args += ['--header', f'{k}: {v}']
            if options.get('data'):
                args += ['--data', options['data']]
            if options.get('tamper'):
                args += ['--tamper', options['tamper']]
            raw = self._exec(args)
            return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        if not raw:
            return results
        # Look for confirmed injection patterns
        re.compile(
            r"Parameter:\s*['\"]?(\S+?)['\"]?\s.*?(is\s+vulnerable|Type:\s*\w+)",
            re.I | re.DOTALL,
        )
        param_blocks = re.split(r'(?=Parameter:)', raw)
        for block in param_blocks:
            match = re.search(r"Parameter:\s*['\"]?(\S+?)['\"]?", block)
            if not match:
                continue
            param = match.group(1)
            types_found = re.findall(r'Type:\s*(.+?)(?:\n|$)', block)
            if not types_found and 'is vulnerable' not in block.lower():
                continue
            technique_str = ', '.join(types_found) if types_found else 'Unknown'
            sev = ToolSeverity.CRITICAL if 'stacked' in technique_str.lower() or 'UNION' in technique_str.upper() else ToolSeverity.HIGH
            results.append(ToolResult(
                tool_name=self.name,
                category='sqli',
                title=f'SQL Injection in parameter: {param}',
                description=f'Injection types: {technique_str}',
                severity=sev,
                confidence=0.95,
                evidence=block[:1500],
                cwe='CWE-89',
                metadata={
                    'parameter': param,
                    'techniques': types_found,
                },
            ))
        # Check for extracted databases/tables
        db_match = re.search(r'available databases.*?:\s*\[.*?\]', raw, re.I | re.DOTALL)
        if db_match:
            for r in results:
                r.metadata['databases_extracted'] = True
        return results


TOOL_CLASS = SqlmapTool
