"""Subjack — Subdomain takeover scanner (Go)."""
from __future__ import annotations

import re
import tempfile
import os
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_VULN_RE = re.compile(
    r'\[\s*(?P<service>[^\]]+)\s*\]\s+(?P<subdomain>\S+)',
    re.I,
)


class SubjackTool(ExternalTool):
    name = 'subjack'
    binary = 'subjack'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.SUBDOMAIN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Check a list of subdomains for takeover opportunities.

        target: single domain OR whitespace-/comma-separated list of subdomains.
        options:
          threads (int): parallel threads (default 100)
          timeout (int): per-request timeout in seconds (default 30)
          ssl (bool): include HTTPS checks (default True)
        """
        if not self.is_available():
            return []
        # Normalise target input — can be newline-separated, comma-separated, or single
        subdomains = [s.strip() for s in re.split(r'[\n,\s]+', target) if s.strip()]
        if not subdomains:
            return []
        # Write to temp file
        fd, tmp_path = tempfile.mkstemp(suffix='.txt', prefix='subjack_')
        try:
            with os.fdopen(fd, 'w') as fh:
                fh.write('\n'.join(subdomains))
            args = [
                self.binary,
                '-w', tmp_path,
                '-t', str(options.get('threads', 100)),
                '-timeout', str(options.get('timeout', 30)),
                '-o', '-',
            ]
            if options.get('ssl', True):
                args.append('-ssl')
            raw = self._exec(args)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.splitlines():
            m = _VULN_RE.search(line)
            if m:
                service = m.group('service').strip()
                subdomain = m.group('subdomain').strip()
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


TOOL_CLASS = SubjackTool
