"""Interactsh-client — OOB interaction server client for SSRF/blind injection detection."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_INTERACTION_SEVERITY: dict[str, ToolSeverity] = {
    'dns': ToolSeverity.MEDIUM,
    'http': ToolSeverity.HIGH,
    'smtp': ToolSeverity.HIGH,
    'ldap': ToolSeverity.HIGH,
    'ftp': ToolSeverity.MEDIUM,
    'smb': ToolSeverity.HIGH,
}


class InteractshTool(ExternalTool):
    """Interactsh client — registers an OOB callback URL and polls for interactions.

    The typical workflow is:
    1. Call ``register()`` to get a unique interaction URL/domain.
    2. Inject that URL into a payload and send it to the target.
    3. Call ``poll()`` (or ``run()`` with poll_seconds) to collect interactions.
    """

    name = 'interactsh'
    binary = 'interactsh-client'
    capabilities = [ToolCapability.VULN_SCAN, ToolCapability.RECON, ToolCapability.OOB]
    default_timeout = 120

    def register(self, **options: Any) -> str | None:
        """Start a session and return the payload URL for injection.

        Returns the interactsh URL string (e.g. 'abc123.interactsh.com'),
        or None if unavailable.
        """
        if not self.is_available():
            return None
        # Run interactsh-client briefly to get the URL printed to stdout
        args = [self.binary, '-json', '-silent', '-v']
        server = options.get('server', 'interactsh.com')
        args += ['-server', server]
        # The URL is printed immediately before waiting for interactions
        # We ask for 0 polling seconds and parse the registration line
        args += ['-poll-interval', '1', '-no-http-server']
        raw = self._exec(args, timeout=10)
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                url = obj.get('url', obj.get('payload', ''))
                if url:
                    return url
            except json.JSONDecodeError:
                import re
                m = re.search(r'([a-z0-9]+\.interactsh\.com)', line, re.I)
                if m:
                    return m.group(1)
        return None

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Poll an existing interactsh session for out-of-band interactions.

        target: the interactsh payload URL/domain returned by register()
        options:
          poll_seconds (int): how long to poll for interactions (default 30)
          server (str): interactsh server (default 'interactsh.com')
        """
        if not self.is_available():
            return []
        poll_seconds = options.get('poll_seconds', 30)
        server = options.get('server', 'interactsh.com')
        args = [
            self.binary,
            '-json',
            '-silent',
            '-server', server,
            '-poll-interval', '5',
        ]
        raw = self._exec(args, timeout=poll_seconds + 30)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Skip registration/status lines
            interaction_type = obj.get('protocol', obj.get('type', ''))
            if not interaction_type or 'url' in obj and not obj.get('interaction'):
                continue
            remote_addr = obj.get('remote-address', obj.get('remote_address', ''))
            full_id = obj.get('full-id', obj.get('unique-id', ''))
            raw_req = obj.get('raw-request', '')
            sev = _INTERACTION_SEVERITY.get(interaction_type.lower(), ToolSeverity.MEDIUM)
            results.append(ToolResult(
                tool_name=self.name,
                category='oob-interaction',
                title=f'OOB {interaction_type.upper()} interaction received from {remote_addr}',
                host=remote_addr,
                severity=sev,
                confidence=0.95,
                metadata={
                    'protocol': interaction_type,
                    'remote': remote_addr,
                    'id': full_id,
                    'raw_request_preview': raw_req[:200] if raw_req else '',
                },
            ))
        return results


TOOL_CLASS = InteractshTool
