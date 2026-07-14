"""s3scanner — Scan S3 buckets for public access."""
from __future__ import annotations

import json
import re
import tempfile
import os
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

# Permission flags reported by s3scanner
_OPEN_PERMS = frozenset({'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'})


class S3ScannerTool(ExternalTool):
    name = 's3scanner'
    binary = 's3scanner'
    capabilities = [ToolCapability.RECON, ToolCapability.OSINT]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Scan one or more S3 bucket names for public access.

        target: single bucket name, or whitespace-/comma-separated list of names.
        options:
          endpoint (str): custom S3-compatible endpoint URL
          threads (int): number of threads (default 4)
        """
        if not self.is_available():
            return []
        buckets = [b.strip() for b in re.split(r'[\n,\s]+', target) if b.strip()]
        if not buckets:
            return []
        fd, tmp_path = tempfile.mkstemp(suffix='.txt', prefix='s3scanner_')
        try:
            with os.fdopen(fd, 'w') as fh:
                fh.write('\n'.join(buckets))
            args = [
                self.binary,
                'scan',
                '--bucket-file', tmp_path,
                '--threads', str(options.get('threads', 4)),
                '--json',
            ]
            endpoint = options.get('endpoint')
            if endpoint:
                args += ['--provider', 'custom', '--endpoint-url', endpoint]
            raw = self._exec(args)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            bucket = obj.get('name', obj.get('bucket', ''))
            exists = obj.get('exists', True)
            perms = obj.get('AllUsers', {}) or {}
            if isinstance(perms, dict):
                granted = [p for p, v in perms.items() if v and p in _OPEN_PERMS]
            else:
                granted = []
            if not bucket or bucket in seen:
                continue
            seen.add(bucket)
            if not exists:
                continue
            if granted:
                sev = ToolSeverity.CRITICAL if 'WRITE' in granted or 'FULL_CONTROL' in granted else ToolSeverity.HIGH
                title = f'S3 bucket {bucket} is publicly {"writable" if "WRITE" in granted else "readable"}: {", ".join(granted)}'
                conf = 0.95
            else:
                sev = ToolSeverity.MEDIUM
                title = f'S3 bucket exists: {bucket}'
                conf = 0.80
            results.append(ToolResult(
                tool_name=self.name,
                category='cloud-storage',
                title=title,
                host=bucket,
                severity=sev,
                confidence=conf,
                metadata={'bucket': bucket, 'public_permissions': granted},
            ))
        return results


TOOL_CLASS = S3ScannerTool
