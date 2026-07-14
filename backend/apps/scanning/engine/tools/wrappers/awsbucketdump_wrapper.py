"""AWSBucketDump — Enumerate contents of public S3 buckets."""
from __future__ import annotations

import re
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_INTERESTING_EXT_RE = re.compile(
    r'\.(key|pem|p12|pfx|env|config|cfg|conf|bak|backup|sql|db|sqlite|'
    r'json|yaml|yml|xml|csv|log|txt|zip|tar\.gz|gz|7z|rar)$',
    re.I,
)
_FOUND_FILE_RE = re.compile(r'\+\s+(?P<key>[\w./\-+%]+)\s+\((?P<size>[\d.]+\s*\w+)\)', re.I)
_BUCKET_RE = re.compile(r'Dumping bucket:\s*(?P<bucket>\S+)', re.I)


class AWSBucketDumpTool(ExternalTool):
    name = 'awsbucketdump'
    binary = 'AWSBucketDump'
    capabilities = [ToolCapability.RECON, ToolCapability.OSINT]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Enumerate accessible files inside a public S3 bucket.

        target: S3 bucket name or URL (s3://bucket or https://bucket.s3.amazonaws.com)
        options:
          interesting_keywords (list[str]): extra filename patterns to flag
          dump_files (bool): download interesting files (default False — enumerate only)
        """
        if not self.is_available():
            return []
        # Strip protocol prefix if provided
        bucket = re.sub(r'^s3://|^https?://([^.]+)\.s3\..*$', r'\1', target).strip('/')
        args = [self.binary, '-l', bucket]
        if not options.get('dump_files', False):
            args.append('-e')  # enumerate only
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        current_bucket = 'unknown'
        seen: set[str] = set()
        for line in raw.splitlines():
            bm = _BUCKET_RE.search(line)
            if bm:
                current_bucket = bm.group('bucket')
                continue
            fm = _FOUND_FILE_RE.search(line)
            if fm:
                key = fm.group('key')
                size = fm.group('size')
                full_key = f'{current_bucket}/{key}'
                if full_key in seen:
                    continue
                seen.add(full_key)
                is_interesting = bool(_INTERESTING_EXT_RE.search(key))
                sev = ToolSeverity.HIGH if is_interesting else ToolSeverity.MEDIUM
                conf = 0.85 if is_interesting else 0.65
                results.append(ToolResult(
                    tool_name=self.name,
                    category='cloud-storage',
                    title=f'Public S3 file: {full_key} ({size})',
                    host=current_bucket,
                    severity=sev,
                    confidence=conf,
                    metadata={
                        'bucket': current_bucket,
                        'key': key,
                        'size': size,
                        'interesting': is_interesting,
                    },
                ))
        return results


TOOL_CLASS = AWSBucketDumpTool
