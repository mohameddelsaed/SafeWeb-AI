"""dnsx — Fast DNS toolkit for bulk resolution and record querying."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class DnsxTool(ExternalTool):
    name = 'dnsx'
    binary = 'dnsx'
    capabilities = [ToolCapability.DNS, ToolCapability.RECON]
    default_timeout = 180

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Resolve a domain or list of domains.

        target: single domain or path to a file of domains.
        options:
          record_types (list[str]): DNS record types to query (default: a, aaaa, cname, mx, ns, txt)
          threads (int): concurrency level (default 50)
          wordlist (str): path to a wordlist for brute-force mode
        """
        if not self.is_available():
            return []

        record_types = options.get('record_types', ['a', 'cname', 'mx', 'ns', 'txt'])
        threads = options.get('threads', 50)

        args = [self.binary, '-silent', '-json', '-resp', '-t', str(threads)]

        # Record type flags
        for rt in record_types:
            args += [f'-{rt}']

        wordlist = options.get('wordlist')
        if wordlist:
            args += ['-w', wordlist]
        else:
            args += ['-d', target]

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
            host = obj.get('host', '')
            status_code = obj.get('status_code', '')
            a_records = obj.get('a', [])
            cname = obj.get('cname', [])
            mx = obj.get('mx', [])
            ns = obj.get('ns', [])
            txt = obj.get('txt', [])

            if status_code == 'NOERROR' or a_records:
                ips = ', '.join(a_records) if a_records else ''
                results.append(ToolResult(
                    tool_name=self.name,
                    category='dns',
                    title=f'DNS: {host}',
                    host=host,
                    severity=ToolSeverity.INFO,
                    confidence=0.95,
                    evidence=f'A={ips} CNAME={cname} MX={mx} NS={ns}',
                    metadata={
                        'a': a_records,
                        'cname': cname,
                        'mx': mx,
                        'ns': ns,
                        'txt': txt,
                        'status': status_code,
                    },
                ))
        return results


TOOL_CLASS = DnsxTool
