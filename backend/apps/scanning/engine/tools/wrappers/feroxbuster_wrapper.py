"""FeroxBuster — Recursive content discovery written in Rust."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

# Project-local SecLists path (matches seclists_manager._DEFAULT_SECLISTS_DIR)
_SECLISTS = Path(__file__).resolve().parents[3] / 'payloads' / 'data' / 'seclists'


class FeroxbusterTool(ExternalTool):
    name = 'feroxbuster'
    binary = 'feroxbuster'
    capabilities = [ToolCapability.WEB_FUZZ, ToolCapability.BRUTE_FORCE]
    default_timeout = 600

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        _default = _SECLISTS / 'Discovery' / 'Web-Content' / 'raft-medium-directories.txt'
        wordlist = options.get('wordlist', str(_default) if _default.exists() else 'raft-medium-directories.txt')
        args = [self.binary, '-u', target, '-w', wordlist, '--json', '-q',
                '-t', str(options.get('threads', 50)),
                '-d', str(options.get('depth', 2))]
        if options.get('extensions'):
            args += ['-x', options['extensions']]
        if options.get('filter_status'):
            args += ['-C', options['filter_status']]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get('type') != 'response':
                continue
            url = obj.get('url', '')
            status = obj.get('status', 0)
            length = obj.get('content_length', 0)
            if status in (200, 204, 301, 302, 307, 401, 403):
                sev = ToolSeverity.LOW if status in (200, 204) else ToolSeverity.INFO
                results.append(ToolResult(
                    tool_name=self.name, category='discovery',
                    title=f'[{status}] {url}',
                    url=url, severity=sev, confidence=0.75,
                    metadata={'status': status, 'length': length},
                ))
        return results

TOOL_CLASS = FeroxbusterTool
