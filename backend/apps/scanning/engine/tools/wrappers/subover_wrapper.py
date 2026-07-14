"""SubOver — Subdomain takeover scanner (Go)."""
from __future__ import annotations

import re
import tempfile
import os
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

# SubOver output: "[SERVICE] subdomain is vulnerable"
_VULN_RE = re.compile(
    r'\[(?P<service>[^\]]+)\]\s+(?P<subdomain>\S+)\s+is\s+vulnerable',
    re.I,
)
_FOUND_RE = re.compile(
    r'\[\+\]\s+Found\s+Vulnerable\s+Subdomain:\s+(?P<subdomain>\S+)',
    re.I,
)


class SubOverTool(ExternalTool):
    name = 'subover'
    binary = 'SubOver'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.SUBDOMAIN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Check subdomains for takeover vulnerabilities.

        target: single domain OR whitespace-/comma-separated list of subdomains.
        options:
          threads (int): parallel threads (default 50)
          timeout (int): HTTP timeout in seconds (default 30)
        """
        if not self.is_available():
            return []
        subdomains = [s.strip() for s in re.split(r'[\n,\s]+', target) if s.strip()]
        if not subdomains:
            return []
        fd, tmp_path = tempfile.mkstemp(suffix='.txt', prefix='subover_')
        try:
            with os.fdopen(fd, 'w') as fh:
                fh.write('\n'.join(subdomains))
            args = [
                self.binary,
                '-l', tmp_path,
                '-t', str(options.get('threads', 50)),
                '-timeout', str(options.get('timeout', 30)),
            ]
            raw = self._exec(args)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            subdomain = service = None
            m = _VULN_RE.search(line)
            if m:
                service = m.group('service').strip()
                subdomain = m.group('subdomain').strip()
            else:
                m2 = _FOUND_RE.search(line)
                if m2:
                    subdomain = m2.group('subdomain').strip()
                    service = 'unknown'
            if subdomain and subdomain not in seen:
                seen.add(subdomain)
                results.append(ToolResult(
                    tool_name=self.name,
                    category='subdomain-takeover',
                    title=f'Subdomain takeover possible: {subdomain} ({service})',
                    host=subdomain,
                    severity=ToolSeverity.HIGH,
                    confidence=0.85,
                    metadata={'vulnerable_service': service, 'subdomain': subdomain},
                ))
        return results


TOOL_CLASS = SubOverTool
