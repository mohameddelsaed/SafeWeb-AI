"""XSStrike — Advanced XSS detection suite."""
from __future__ import annotations

import re
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class XsStrikeTool(ExternalTool):
    name = 'xsstrike'
    binary = 'xsstrike'
    capabilities = [ToolCapability.VULN_SCAN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Scan target URL for XSS vulnerabilities.

        options:
          crawl (bool): enable crawl mode (default True)
          blind (bool): inject blind XSS payloads (default False)
          level (int): crawl depth level (default 2)
        """
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '--json']
        if options.get('crawl', True):
            args.append('--crawl')
            lvl = options.get('level', 2)
            args += ['-l', str(lvl)]
        if options.get('blind', False):
            args.append('--blind')
        raw = self._exec(args)
        return self.parse_output(raw, target=target)

    # XSStrike doesn't always have clean JSON — parse both formats
    def parse_output(self, raw: str, target: str = '') -> list[ToolResult]:
        results = []
        # Try JSON first (--json flag)
        try:
            import json
            data = json.loads(raw)
            for item in data if isinstance(data, list) else [data]:
                url = item.get('url', target)
                param = item.get('param', '')
                payload = item.get('payload', '')
                results.append(ToolResult(
                    tool_name=self.name,
                    category='xss',
                    title=f'XSS found in parameter "{param}"',
                    host=url,
                    severity=ToolSeverity.HIGH,
                    confidence=0.85,
                    metadata={'url': url, 'param': param, 'payload': payload},
                ))
        except Exception:
            # Fallback: parse plain-text output
            for line in raw.splitlines():
                if any(kw in line.lower() for kw in ('xss vulnerability', 'payload found', 'reflected')):
                    m = re.search(r'parameter[s]?\s+["\']?(\w+)["\']?', line, re.I)
                    param = m.group(1) if m else 'unknown'
                    results.append(ToolResult(
                        tool_name=self.name,
                        category='xss',
                        title=f'Potential XSS in parameter "{param}"',
                        host=target,
                        severity=ToolSeverity.HIGH,
                        confidence=0.70,
                        metadata={'raw_line': line},
                    ))
        return results


TOOL_CLASS = XsStrikeTool
