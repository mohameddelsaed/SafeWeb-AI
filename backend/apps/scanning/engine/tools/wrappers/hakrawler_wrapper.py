"""Hakrawler — Fast web crawler for URL and endpoint discovery."""
from __future__ import annotations

from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class HakrawlerTool(ExternalTool):
    name = 'hakrawler'
    binary = 'hakrawler'
    capabilities = [ToolCapability.CRAWLER, ToolCapability.RECON]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Crawl a URL for links, forms, JS files, and endpoints.

        options:
          depth (int): crawl depth (default 3)
          subs (bool): include subdomains (default True)
          plain (bool): plain output — one URL per line (default True)
        """
        if not self.is_available():
            return []
        depth = options.get('depth', 3)
        # hakrawler reads target from stdin
        args = [self.binary, '-d', str(depth), '-u']
        if options.get('subs', True):
            args += ['-subs']
        # Run via echo pipe: hakrawler reads from stdin
        import subprocess
        try:
            proc = subprocess.run(
                args,
                input=target,
                capture_output=True,
                text=True,
                timeout=self.default_timeout,
            )
            raw = proc.stdout
        except (subprocess.TimeoutExpired, OSError):
            raw = ''
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            url = line.strip()
            if not url or not url.startswith('http') or url in seen:
                continue
            seen.add(url)
            results.append(ToolResult(
                tool_name=self.name,
                category='url',
                title=f'URL: {url}',
                url=url,
                severity=ToolSeverity.INFO,
                confidence=0.80,
                metadata={'source': 'hakrawler'},
            ))
        return results


TOOL_CLASS = HakrawlerTool
