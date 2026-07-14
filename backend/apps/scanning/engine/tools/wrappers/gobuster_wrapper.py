"""Gobuster — Directory/file/vhost/DNS/S3 brute-forcer."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

try:
    from ...payloads.seclists_manager import SecListsManager as _SecListsManager
    _SECLISTS_DIR = _SecListsManager().base_dir
except Exception:
    _SECLISTS_DIR = None  # type: ignore[assignment]

# Prefer SecLists raft-medium-directories; fall back to system dirb list
def _default_wordlist() -> str:
    if _SECLISTS_DIR:
        candidate = Path(_SECLISTS_DIR) / 'Discovery' / 'Web-Content' / 'raft-medium-directories.txt'
        if candidate.is_file():
            return str(candidate)
    return '/usr/share/wordlists/dirb/common.txt'

# Status codes that indicate interesting findings
_HIGH_VALUE_CODES = frozenset({200, 201, 301, 302, 307, 401, 403, 500})

_LINE_RE = re.compile(
    r'^(?P<path>/\S*)\s+\(Status:\s*(?P<code>\d+)\)(?:.*\[Size:\s*(?P<size>\d+)\])?',
)


class GobusterTool(ExternalTool):
    name = 'gobuster'
    binary = 'gobuster'
    capabilities = [ToolCapability.WEB_FUZZ, ToolCapability.BRUTE_FORCE]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Brute-force directories, files, DNS subdomains, or VHosts.

        target: Base URL (dir mode) or domain (dns/vhost mode)
        options:
          mode (str): 'dir' | 'dns' | 'vhost' | 's3' (default 'dir')
          wordlist (str): path to wordlist file (default system wordlist)
          extensions (str): comma-separated extensions (e.g. 'php,html,txt')
          threads (int): number of goroutines (default 30)
          status_codes (str): comma-separated status codes to show (default '200,204,301,302,307,401,403')
          follow_redirect (bool): follow redirects (default False)
        """
        if not self.is_available():
            return []
        mode = options.get('mode', 'dir')
        wordlist = options.get('wordlist', _default_wordlist())
        args = [
            self.binary,
            mode,
            '-u' if mode in ('dir', 'vhost') else '-d', target,
            '-w', wordlist,
            '-q',
            '--no-error',
            '-t', str(options.get('threads', 30)),
        ]
        exts = options.get('extensions')
        if exts and mode == 'dir':
            args += ['-x', exts]
        codes = options.get('status_codes', '200,204,301,302,307,401,403')
        if mode == 'dir':
            args += ['-s', codes]
        if options.get('follow_redirect', False):
            args.append('-r')
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _LINE_RE.match(line)
            if m:
                path = m.group('path')
                code = int(m.group('code'))
                size = int(m.group('size') or 0)
            else:
                # DNS/vhost output: bare subdomain
                path = line
                code = 0
                size = 0
            if path in seen:
                continue
            seen.add(path)
            if code in (401, 403):
                sev, conf = ToolSeverity.MEDIUM, 0.80
            elif code == 200:
                sev, conf = ToolSeverity.INFO, 0.90
            elif code in (301, 302, 307):
                sev, conf = ToolSeverity.INFO, 0.85
            elif code == 500:
                sev, conf = ToolSeverity.MEDIUM, 0.75
            else:
                sev, conf = ToolSeverity.INFO, 0.70
            results.append(ToolResult(
                tool_name=self.name,
                category='directory-brute',
                title=f'Found: {path}' + (f' [{code}]' if code else ''),
                host='',
                severity=sev,
                confidence=conf,
                metadata={'path': path, 'status_code': code, 'size': size},
            ))
        return results


TOOL_CLASS = GobusterTool
