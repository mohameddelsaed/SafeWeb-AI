"""SecretFinder — Discover sensitive data in JavaScript files."""
from __future__ import annotations

import re
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

# Map common secret categories to severity levels
_SECRET_SEVERITY: dict[str, ToolSeverity] = {
    'google_api': ToolSeverity.HIGH,
    'firebase': ToolSeverity.HIGH,
    'google_captcha': ToolSeverity.MEDIUM,
    'amazon_aws_access_key_id': ToolSeverity.CRITICAL,
    'amazon_mws_auth_toke': ToolSeverity.CRITICAL,
    'amazon_aws_url': ToolSeverity.HIGH,
    'facebook_access_token': ToolSeverity.HIGH,
    'authorization_basic': ToolSeverity.HIGH,
    'authorization_bearer': ToolSeverity.HIGH,
    'mailgun_api_key': ToolSeverity.HIGH,
    'twilio_api_key': ToolSeverity.HIGH,
    'stripe_api_key': ToolSeverity.CRITICAL,
    'github_access_token': ToolSeverity.CRITICAL,
    'private_ssh_key': ToolSeverity.CRITICAL,
    'slack_token': ToolSeverity.HIGH,
}
_DEFAULT_SEV = ToolSeverity.MEDIUM

# SecretFinder CLI output: "[!] MatchType: ... | Match: ..."
_MATCH_RE = re.compile(r'\[!\]\s+MatchType:\s*(?P<mtype>[^|]+?)\s*\|\s*Match:\s*(?P<match>.+)', re.I)


class SecretFinderTool(ExternalTool):
    name = 'secretfinder'
    binary = 'secretfinder'
    capabilities = [ToolCapability.RECON, ToolCapability.CREDENTIAL, ToolCapability.SECRET_SCAN]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Scan a JS URL or file for embedded secrets/tokens.

        target: URL (https://...) or local file path of a JS file
        options:
          output (str): 'cli' (default) or 'html'
          pattern (str): custom regex pattern to add
        """
        if not self.is_available():
            return []
        args = [self.binary, '-i', target, '-o', options.get('output', 'cli')]
        pattern = options.get('pattern')
        if pattern:
            args += ['-r', pattern]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _MATCH_RE.search(line)
            if m:
                mtype = m.group('mtype').strip().lower().replace(' ', '_')
                match_val = m.group('match').strip()
                key = f'{mtype}:{match_val[:80]}'
                if key in seen:
                    continue
                seen.add(key)
                sev = _SECRET_SEVERITY.get(mtype, _DEFAULT_SEV)
                display = match_val[:80] + '...' if len(match_val) > 80 else match_val
                results.append(ToolResult(
                    tool_name=self.name,
                    category='secret-in-js',
                    title=f'Secret in JS: {mtype}',
                    host='',
                    severity=sev,
                    confidence=0.75,
                    metadata={'type': mtype, 'match_preview': display},
                ))
        return results


TOOL_CLASS = SecretFinderTool
