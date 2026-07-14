"""EyeWitness — Web application screenshot and analysis tool."""
from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_INTERESTING_RE = re.compile(
    r'(login|admin|dashboard|portal|console|management|jenkins|gitlab|kibana|grafana|'
    r'phpmyadmin|wp-admin|webmin|jira|confluence)',
    re.I,
)


class EyeWitnessTool(ExternalTool):
    name = 'eyewitness'
    binary = 'eyewitness'
    capabilities = [ToolCapability.RECON, ToolCapability.SCREENSHOT]
    default_timeout = 600

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Screenshot and fingerprint web targets.

        target: single URL, or whitespace-/newline-separated list of URLs.
        options:
          timeout (int): per-page timeout in seconds (default 30)
          threads (int): number of threads (default 5)
          output_dir (str): path for screenshot output (default tmp dir)
          jitter (int): random jitter time in ms (default 0)
        """
        if not self.is_available():
            return []
        urls = [u.strip() for u in re.split(r'[\n\s]+', target) if u.strip()]
        if not urls:
            return []
        use_tmpdir = not options.get('output_dir')
        tmpdir = options.get('output_dir') or tempfile.mkdtemp(prefix='eyewitness_')
        fd, url_file = tempfile.mkstemp(suffix='.txt', prefix='ew_urls_')
        try:
            with os.fdopen(fd, 'w') as fh:
                fh.write('\n'.join(urls))
            args = [
                self.binary,
                '--web',
                '-f', url_file,
                '--no-prompt',
                '-d', tmpdir,
                '--timeout', str(options.get('timeout', 30)),
                '--threads', str(options.get('threads', 5)),
            ]
            jitter = options.get('jitter', 0)
            if jitter:
                args += ['--jitter', str(jitter)]
            raw = self._exec(args)
        finally:
            try:
                os.unlink(url_file)
            except OSError:
                pass
        # Try to parse the JSON report written by EyeWitness
        report_json = os.path.join(tmpdir, 'report.json')
        if os.path.exists(report_json):
            with open(report_json, 'r', encoding='utf-8') as fh:
                report_raw = fh.read()
        else:
            report_raw = raw
        results = self.parse_output(report_raw)
        if use_tmpdir and not results:
            # Clean up empty tmp dir
            try:
                import shutil
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass
        return results

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        # Try JSON report
        try:
            data = json.loads(raw)
            pages = data if isinstance(data, list) else data.get('results', [])
            for page in pages:
                url = page.get('url', '')
                title = page.get('title', '')
                screenshot = page.get('screenshot_path', '')
                headers = page.get('headers', {})
                server = headers.get('Server', headers.get('server', '')) if isinstance(headers, dict) else ''
                is_interesting = bool(_INTERESTING_RE.search(url) or _INTERESTING_RE.search(title))
                results.append(ToolResult(
                    tool_name=self.name,
                    category='web-screenshot',
                    title=f'Screenshot: {url}' + (f' — {title}' if title else ''),
                    host=url,
                    severity=ToolSeverity.MEDIUM if is_interesting else ToolSeverity.INFO,
                    confidence=0.90,
                    metadata={
                        'url': url,
                        'title': title,
                        'server': server,
                        'screenshot': screenshot,
                        'interesting': is_interesting,
                    },
                ))
        except (json.JSONDecodeError, TypeError):
            # Fallback: parse plain-text summary lines
            for line in raw.splitlines():
                line = line.strip()
                m = re.search(r'https?://\S+', line)
                if m:
                    url = m.group(0)
                    is_interesting = bool(_INTERESTING_RE.search(url))
                    results.append(ToolResult(
                        tool_name=self.name,
                        category='web-screenshot',
                        title=f'Screenshot: {url}',
                        host=url,
                        severity=ToolSeverity.MEDIUM if is_interesting else ToolSeverity.INFO,
                        confidence=0.70,
                        metadata={'url': url, 'interesting': is_interesting},
                    ))
        return results


TOOL_CLASS = EyeWitnessTool
