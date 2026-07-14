"""Aquatone — Web asset visual discovery tool using Chrome headless."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_INTERESTING_RE = re.compile(
    r'(login|admin|dashboard|portal|console|management|jenkins|gitlab|kibana|grafana|'
    r'phpmyadmin|wp-admin|webmin|jira|confluence)',
    re.I,
)


class AquatoneTool(ExternalTool):
    name = 'aquatone'
    binary = 'aquatone'
    capabilities = [ToolCapability.RECON, ToolCapability.SCREENSHOT]
    default_timeout = 600

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Screenshot and fingerprint a list of URLs using aquatone.

        target: single URL, or whitespace-/newline-separated list of URLs.
        options:
          timeout (int): browser timeout ms (default 50000)
          threads (int): number of threads (default 5)
          output_dir (str): output directory (default tmp)
          screenshot_timeout (int): screenshot timeout ms (default 30000)
        """
        if not self.is_available():
            return []
        urls = [u.strip() for u in re.split(r'[\n\s]+', target) if u.strip()]
        if not urls:
            return []
        tmpdir = options.get('output_dir') or tempfile.mkdtemp(prefix='aquatone_')
        url_input = '\n'.join(urls).encode()
        args = [
            self.binary,
            '-out', tmpdir,
            '-timeout', str(options.get('timeout', 50000)),
            '-threads', str(options.get('threads', 5)),
            '-screenshot-timeout', str(options.get('screenshot_timeout', 30000)),
            '-silent',
            '-json-output',
        ]
        try:
            proc = subprocess.run(
                args,
                input=url_input,
                capture_output=True,
                timeout=self.default_timeout,
            )
            raw = proc.stdout.decode(errors='replace') + proc.stderr.decode(errors='replace')
        except (subprocess.TimeoutExpired, FileNotFoundError):
            raw = ''
        # Look for aquatone_urls.json in output dir
        json_report = os.path.join(tmpdir, 'aquatone_urls.json')
        if os.path.exists(json_report):
            with open(json_report, 'r', encoding='utf-8') as fh:
                report_raw = fh.read()
        else:
            report_raw = raw
        return self.parse_output(report_raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        seen: set[str] = set()
        try:
            data = json.loads(raw)
            pages = data if isinstance(data, list) else data.get('pages', list(data.values()) if isinstance(data, dict) else [])
            for page in pages:
                url = page.get('url', page.get('URL', ''))
                status = page.get('status', page.get('Status', 0))
                title = page.get('title', page.get('PageTitle', ''))
                screenshot = page.get('screenshot_path', page.get('ScreenshotPath', ''))
                if not url or url in seen:
                    continue
                seen.add(url)
                is_interesting = bool(_INTERESTING_RE.search(url) or _INTERESTING_RE.search(title or ''))
                results.append(ToolResult(
                    tool_name=self.name,
                    category='web-screenshot',
                    title=f'Screenshot: {url}' + (f' [{status}]' if status else ''),
                    host=url,
                    severity=ToolSeverity.MEDIUM if is_interesting else ToolSeverity.INFO,
                    confidence=0.85,
                    metadata={
                        'url': url,
                        'status': status,
                        'title': title,
                        'screenshot': screenshot,
                        'interesting': is_interesting,
                    },
                ))
        except (json.JSONDecodeError, TypeError):
            for line in raw.splitlines():
                m = re.search(r'https?://\S+', line)
                if m:
                    url = m.group(0)
                    if url not in seen:
                        seen.add(url)
                        is_interesting = bool(_INTERESTING_RE.search(url))
                        results.append(ToolResult(
                            tool_name=self.name,
                            category='web-screenshot',
                            title=f'Screenshot: {url}',
                            host=url,
                            severity=ToolSeverity.MEDIUM if is_interesting else ToolSeverity.INFO,
                            confidence=0.65,
                            metadata={'url': url, 'interesting': is_interesting},
                        ))
        return results


TOOL_CLASS = AquatoneTool
