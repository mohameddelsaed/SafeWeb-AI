"""cloud_enum — Multi-cloud asset enumeration (AWS S3, Azure, GCP)."""
from __future__ import annotations

import json
import re
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

_OPEN_RE = re.compile(r'\[open\]|\(open\)|OPEN|public', re.I)
_BUCKET_RE = re.compile(r'(s3://|\.s3\.|\.blob\.core\.|storage\.googleapis\.)', re.I)


class CloudEnumTool(ExternalTool):
    name = 'cloud_enum'
    binary = 'cloud_enum'
    capabilities = [ToolCapability.RECON, ToolCapability.OSINT]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Enumerate cloud resources (S3, Azure blobs, GCS) for a keyword.

        target: company/keyword to search (e.g. 'targetcorp')
        options:
          keywords (list[str]): additional keyword list
          disable_aws (bool): skip AWS enumeration
          disable_azure (bool): skip Azure enumeration
          disable_gcp (bool): skip GCP enumeration
          threads (int): number of threads (default 10)
        """
        if not self.is_available():
            return []
        args = [self.binary, '-k', target]
        extra_keywords = options.get('keywords', [])
        for kw in extra_keywords:
            args += ['-k', kw]
        if options.get('disable_aws'):
            args.append('--disable-aws')
        if options.get('disable_azure'):
            args.append('--disable-azure')
        if options.get('disable_gcp'):
            args.append('--disable-gcp')
        threads = options.get('threads', 10)
        args += ['-t', str(threads)]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results: list[ToolResult] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # Try JSON line
            try:
                obj = json.loads(line)
                resource = obj.get('name', obj.get('url', ''))
                is_open = obj.get('open', obj.get('public', False))
                provider = obj.get('provider', 'unknown')
            except json.JSONDecodeError:
                # Plain text line
                if not _BUCKET_RE.search(line) and 'bucket' not in line.lower() and 'blob' not in line.lower():
                    continue
                resource = line
                is_open = bool(_OPEN_RE.search(line))
                provider = (
                    'aws' if '.s3.' in line or 's3://' in line else
                    'azure' if '.blob.core.' in line else
                    'gcp' if 'storage.googleapis.' in line else 'unknown'
                )
            if not resource or resource in seen:
                continue
            seen.add(resource)
            sev = ToolSeverity.HIGH if is_open else ToolSeverity.MEDIUM
            conf = 0.85 if is_open else 0.65
            results.append(ToolResult(
                tool_name=self.name,
                category='cloud-asset',
                title=f'Cloud resource: {resource}{"  [PUBLIC]" if is_open else ""}',
                host=resource,
                severity=sev,
                confidence=conf,
                metadata={'provider': provider, 'public': is_open, 'resource': resource},
            ))
        return results


TOOL_CLASS = CloudEnumTool
