"""puredns — Fast domain bruteforce and validation with wildcard filtering."""
from __future__ import annotations

import os
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


# Default public resolvers bundled as a fallback
_DEFAULT_RESOLVERS = [
    '1.1.1.1', '8.8.8.8', '8.8.4.4', '9.9.9.9',
    '208.67.222.222', '208.67.220.220', '64.6.64.6',
]


class PurednsTO(ExternalTool):
    name = 'puredns'
    binary = 'puredns'
    capabilities = [ToolCapability.DNS, ToolCapability.SUBDOMAIN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Brute-force or resolve subdomains with wildcard filtering.

        target: domain to brute-force.
        options:
          wordlist (str): path to subdomain wordlist (required for bruteforce mode)
          resolvers_file (str): path to resolvers list
          resolve_list (str): path to pre-existing subdomain list to resolve
          threads (int): resolver thread count (default 100)
        """
        if not self.is_available():
            return []

        resolvers_file = options.get('resolvers_file')
        if not resolvers_file:
            # Write a temp resolvers file
            import tempfile
            tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.txt', delete=False, prefix='puredns_resolvers_'
            )
            tmp.write('\n'.join(_DEFAULT_RESOLVERS))
            tmp.close()
            resolvers_file = tmp.name
            _cleanup = True
        else:
            _cleanup = False

        try:
            threads = options.get('threads', 100)
            resolve_list = options.get('resolve_list')
            wordlist = options.get('wordlist')

            if resolve_list:
                # Resolve mode: validate an existing list
                args = [
                    self.binary, 'resolve', resolve_list,
                    '-r', resolvers_file,
                    '--threads', str(threads),
                    '--write-wildcards',
                ]
            elif wordlist:
                # Bruteforce mode
                args = [
                    self.binary, 'bruteforce', wordlist, target,
                    '-r', resolvers_file,
                    '--threads', str(threads),
                    '--write-wildcards',
                ]
            else:
                return []

            raw = self._exec(args)
        finally:
            if _cleanup:
                try:
                    os.unlink(resolvers_file)
                except OSError:
                    pass

        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            host = line.strip().lower()
            if not host or '.' not in host or host in seen:
                continue
            if ' ' in host or host.startswith('['):
                continue
            seen.add(host)
            results.append(ToolResult(
                tool_name=self.name,
                category='subdomain',
                title=f'Subdomain: {host}',
                host=host,
                severity=ToolSeverity.INFO,
                confidence=0.92,  # High confidence: wildcard-filtered
                metadata={'source': 'puredns', 'wildcard_filtered': True},
            ))
        return results


TOOL_CLASS = PurednsTO
