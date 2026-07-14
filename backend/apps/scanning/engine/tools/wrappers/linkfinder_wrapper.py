"""LinkFinder — Find endpoints in JavaScript files."""
from __future__ import annotations

import re
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_INTERESTING_PATH_RE = re.compile(
    r'(/api/|/admin|/internal|/v[0-9]/|\.php|\.asp|/auth|/login|/token|/key)',
    re.I,
)


class LinkFinderTool(ExternalTool):
    name = 'linkfinder'
    binary = 'linkfinder'
    capabilities = [ToolCapability.RECON, ToolCapability.CRAWLER]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Extract endpoints from a JavaScript file or URL.

        target: URL or local file path of a JS file, or a base URL to crawl.
        options:
          inside (bool): search also inside bundled code (default False)
          output (str): output format — 'cli' (default) or 'html'
        """
        if not self.is_available():
            return []
        args = [self.binary, '-i', target, '-o', options.get('output', 'cli')]
        if options.get('inside', False):
            args.append('--inside')
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        endpoints: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith('[') and 'LinkFinder' in line:
                continue
            # Lines are endpoint paths or full URLs
            if line not in endpoints:
                endpoints.add(line)
                is_interesting = bool(_INTERESTING_PATH_RE.search(line))
                results.append(ToolResult(
                    tool_name=self.name,
                    category='js-endpoint',
                    title=f'Endpoint discovered: {line}',
                    host='',
                    severity=ToolSeverity.MEDIUM if is_interesting else ToolSeverity.INFO,
                    confidence=0.75,
                    metadata={'endpoint': line, 'interesting': is_interesting},
                ))
        return results


TOOL_CLASS = LinkFinderTool
