"""Gitleaks — Detect secrets in git repos."""
from __future__ import annotations

import json
import os
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class GitleaksTool(ExternalTool):
    name = 'gitleaks'
    binary = 'gitleaks'
    capabilities = [ToolCapability.CREDENTIAL, ToolCapability.RECON, ToolCapability.SECRET_SCAN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Scan a local repository or directory path for leaked secrets.

        target: local git repository or directory path
        options:
          log_opts (str): git log options (e.g. '--since=2weeks')
          config (str): custom gitleaks config file path
        """
        if not self.is_available():
            return []
        import tempfile
        fd, report_path = tempfile.mkstemp(suffix='.json', prefix='gitleaks_')
        os.close(fd)
        try:
            args = [
                self.binary,
                'detect',
                '--source', target,
                '--report-format', 'json',
                '--report-path', report_path,
                '--no-banner',
            ]
            config = options.get('config')
            if config:
                args += ['--config', config]
            log_opts = options.get('log_opts')
            if log_opts:
                args += ['--log-opts', log_opts]
            # Gitleaks exits 1 when leaks found — capture output regardless
            self._exec(args)
            with open(report_path, 'r', encoding='utf-8') as fh:
                raw = fh.read()
        except Exception:
            raw = ''
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        if not raw.strip():
            return results
        try:
            leaks = json.loads(raw)
        except json.JSONDecodeError:
            return results
        if not isinstance(leaks, list):
            leaks = [leaks]
        for leak in leaks:
            rule = leak.get('RuleID', leak.get('rule', 'unknown'))
            secret = leak.get('Secret', leak.get('secret', ''))
            file_path = leak.get('File', leak.get('file', ''))
            line_num = leak.get('StartLine', leak.get('line', 0))
            commit = leak.get('Commit', '')
            author = leak.get('Author', '')
            secret_display = secret[:60] + '...' if len(secret) > 60 else secret
            results.append(ToolResult(
                tool_name=self.name,
                category='secret-exposure',
                title=f'Secret leaked: {rule}',
                host='',
                severity=ToolSeverity.HIGH,
                confidence=0.80,
                metadata={
                    'rule': rule,
                    'file': file_path,
                    'line': line_num,
                    'commit': commit,
                    'author': author,
                    'secret_preview': secret_display,
                },
            ))
        return results


TOOL_CLASS = GitleaksTool
