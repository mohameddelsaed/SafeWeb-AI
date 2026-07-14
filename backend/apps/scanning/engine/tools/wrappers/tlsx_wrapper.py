"""tlsx — Fast TLS certificate grabber and analyser by ProjectDiscovery."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity

# TLS versions considered weak/insecure
_WEAK_TLS = {'ssl30', 'tls10', 'tls11'}


class TlsxTool(ExternalTool):
    name = 'tlsx'
    binary = 'tlsx'
    capabilities = [ToolCapability.RECON, ToolCapability.NETWORK]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        """Grab TLS certificate and handshake info.

        target: hostname or host:port.
        options:
          san (bool): extract Subject Alternative Names (default True)
          cn  (bool): extract Common Name (default True)
          port (int): TLS port (default 443)
        """
        if not self.is_available():
            return []
        args = [self.binary, '-u', target, '-json', '-silent']
        if options.get('san', True):
            args += ['-san']
        if options.get('cn', True):
            args += ['-cn']
        if options.get('so', True):
            args += ['-so']   # Subject Org
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
            host = obj.get('host', '')
            port = obj.get('port', 443)
            version = (obj.get('version') or '').lower()
            cn = obj.get('subject_cn', '')
            sans = obj.get('subject_an', []) or []
            org = obj.get('subject_org', [])
            issuer = obj.get('issuer_cn', '')
            not_after = obj.get('not_after', '')
            cipher = obj.get('cipher', '')
            expired = obj.get('expired', False)

            sev = ToolSeverity.INFO
            issues = []

            if version and version.replace('v', '').replace('.', '') in _WEAK_TLS:
                sev = ToolSeverity.HIGH
                issues.append(f'Weak TLS version: {version}')
            if expired:
                sev = ToolSeverity.HIGH
                issues.append('Certificate is EXPIRED')

            results.append(ToolResult(
                tool_name=self.name,
                category='tls',
                title=f'TLS: {host}:{port} ({version}) CN={cn}',
                description='; '.join(issues) if issues else f'TLS OK — {version}',
                host=host,
                port=port,
                severity=sev,
                confidence=0.95,
                evidence=f'CN={cn} Issuer={issuer} NotAfter={not_after} Cipher={cipher}',
                metadata={
                    'version': version,
                    'cn': cn,
                    'sans': sans,
                    'org': org,
                    'issuer': issuer,
                    'cipher': cipher,
                    'expired': expired,
                    'not_after': not_after,
                },
            ))
        return results


TOOL_CLASS = TlsxTool
