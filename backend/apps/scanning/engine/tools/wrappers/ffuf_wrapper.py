"""Ffuf — Fast web fuzzer for directory/parameter/vhost brute-forcing."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

# Project-local SecLists path (matches seclists_manager._DEFAULT_SECLISTS_DIR)
_SECLISTS = Path(__file__).resolve().parents[3] / 'payloads' / 'data' / 'seclists'


class FfufTool(ExternalTool):
    name = 'ffuf'
    binary = 'ffuf'
    capabilities = [ToolCapability.WEB_FUZZ, ToolCapability.BRUTE_FORCE, ToolCapability.CRAWLER]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        _default = _SECLISTS / 'Discovery' / 'Web-Content' / 'common.txt'
        wordlist = options.get('wordlist', str(_default) if _default.exists() else 'common.txt')
        mode = options.get('mode', 'dir')  # dir, param, vhost
        args = [self.binary, '-u', target, '-w', wordlist, '-o', '/dev/stdout', '-of', 'json', '-s']
        if mode == 'dir' and 'FUZZ' not in target:
            args[2] = target.rstrip('/') + '/FUZZ'
        mc = options.get('match_codes', '200,204,301,302,307,401,403,405')
        args += ['-mc', mc]
        fc = options.get('filter_codes')
        if fc:
            args += ['-fc', fc]
        fs = options.get('filter_size')
        if fs:
            args += ['-fs', str(fs)]
        rate = options.get('rate', 100)
        args += ['-rate', str(rate)]
        threads = options.get('threads', 40)
        args += ['-t', str(threads)]
        if options.get('headers'):
            for k, v in options['headers'].items():
                args += ['-H', f'{k}: {v}']
        if options.get('cookie'):
            args += ['-H', f'Cookie: {options["cookie"]}']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        if not raw:
            return results
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return results
        for item in data.get('results', []):
            status = item.get('status', 0)
            url = item.get('url', '')
            length = item.get('length', 0)
            words = item.get('words', 0)
            ipt = item.get('input', {})
            fuzz_val = ipt.get('FUZZ', '') if isinstance(ipt, dict) else ''
            sev = ToolSeverity.INFO
            if status in (200, 204):
                sev = ToolSeverity.LOW
            elif status in (401, 403):
                sev = ToolSeverity.MEDIUM
            results.append(ToolResult(
                tool_name=self.name,
                category='discovery',
                title=f'Found: {fuzz_val} (HTTP {status})',
                url=url,
                severity=sev,
                confidence=0.75,
                metadata={
                    'status': status,
                    'length': length,
                    'words': words,
                    'fuzz_value': fuzz_val,
                },
            ))
        return results


TOOL_CLASS = FfufTool
