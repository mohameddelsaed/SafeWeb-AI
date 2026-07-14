"""httprobe — Probe a list of domains for live HTTP/HTTPS services."""
from __future__ import annotations

import subprocess
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class HttpprobeTool(ExternalTool):
    name = 'httprobe'
    binary = 'httprobe'
    capabilities = [ToolCapability.RECON]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Probe one or more hosts for live HTTP/HTTPS.

        target: single hostname or newline-separated list of hostnames.
        options:
          concurrency (int): concurrent probes (default 20)
          timeout (int): per-probe timeout in ms (default 10000)
          prefer_https (bool): output HTTPS when both available (default False)
        """
        if not self.is_available():
            return []
        concurrency = options.get('concurrency', 20)
        timeout_ms = options.get('timeout', 10000)
        args = [self.binary, '-c', str(concurrency), '-t', str(timeout_ms)]
        if options.get('prefer_https', False):
            args += ['-prefer-https']

        # httprobe reads host list from stdin
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
                category='live-host',
                title=f'Live: {url}',
                url=url,
                severity=ToolSeverity.INFO,
                confidence=0.95,
                metadata={'source': 'httprobe'},
            ))
        return results


TOOL_CLASS = HttpprobeTool
