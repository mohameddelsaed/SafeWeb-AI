"""GetJS — Extract JavaScript file URLs from a web page."""
from __future__ import annotations

from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class GetJSTool(ExternalTool):
    name = 'getJS'
    binary = 'getJS'
    capabilities = [ToolCapability.RECON, ToolCapability.CRAWLER]
    default_timeout = 60

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Extract JS file URLs from target page.

        options:
          complete (bool): resolve relative URLs to absolute (default True)
        """
        if not self.is_available():
            return []
        args = [self.binary, '--url', target]
        if options.get('complete', True):
            args += ['--complete']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            if not url.startswith('http') and not url.startswith('/'):
                continue
            seen.add(url)
            results.append(ToolResult(
                tool_name=self.name,
                category='javascript',
                title=f'JS file: {url}',
                url=url,
                severity=ToolSeverity.INFO,
                confidence=0.90,
                metadata={'type': 'js_file'},
            ))
        return results


TOOL_CLASS = GetJSTool
