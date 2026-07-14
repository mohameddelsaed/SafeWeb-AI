"""TruffleHog — Find secrets in git repos and filesystems."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class TruffleHogTool(ExternalTool):
    name = 'trufflehog'
    binary = 'trufflehog'
    capabilities = [ToolCapability.CREDENTIAL, ToolCapability.RECON, ToolCapability.SECRET_SCAN]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Scan a git repository URL or local filesystem path for secrets.

        target: git repo URL (https://...) or local filesystem path
        options:
          source (str): override source type — 'git', 'github', 'filesystem' (auto-detected)
          branch (str): git branch to scan
          since_commit (str): scan only commits since this SHA
          only_verified (bool): report only verified credentials (default False)
        """
        if not self.is_available():
            return []
        only_verified = options.get('only_verified', False)
        # Auto-detect source type
        source = options.get('source')
        if not source:
            if target.startswith('https://github.com') or target.startswith('http://github.com'):
                source = 'github'
            elif target.startswith('https://') or target.startswith('http://') or target.startswith('git@'):
                source = 'git'
            else:
                source = 'filesystem'

        args = [self.binary, source, target, '--json', '--no-update']
        if only_verified:
            args.append('--only-verified')
        branch = options.get('branch')
        if branch and source in ('git', 'github'):
            args += ['--branch', branch]
        since = options.get('since_commit')
        if since and source in ('git', 'github'):
            args += ['--since-commit', since]

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
            detector = obj.get('DetectorName', obj.get('detector_name', 'unknown'))
            raw_val = obj.get('Raw', obj.get('raw', ''))
            verified = obj.get('Verified', obj.get('verified', False))
            source_meta = obj.get('SourceMetadata', {})
            file_path = ''
            line_num = 0
            if isinstance(source_meta, dict):
                data = source_meta.get('Data', {})
                if isinstance(data, dict):
                    git = data.get('Git', data.get('Filesystem', {}))
                    if isinstance(git, dict):
                        file_path = git.get('file', git.get('filename', ''))
                        line_num = git.get('line', 0)
            sev = ToolSeverity.CRITICAL if verified else ToolSeverity.HIGH
            conf = 0.95 if verified else 0.70
            # Truncate raw secret value for safety
            raw_display = raw_val[:60] + '...' if len(raw_val) > 60 else raw_val
            results.append(ToolResult(
                tool_name=self.name,
                category='secret-exposure',
                title=f'Secret found: {detector}{"  (verified)" if verified else ""}',
                host='',
                severity=sev,
                confidence=conf,
                metadata={
                    'detector': detector,
                    'verified': verified,
                    'file': file_path,
                    'line': line_num,
                    'raw_preview': raw_display,
                },
            ))
        return results


TOOL_CLASS = TruffleHogTool
