"""ASNmap — ASN-based network range discovery by ProjectDiscovery."""
from __future__ import annotations

import json
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class AsnmapTool(ExternalTool):
    name = 'asnmap'
    binary = 'asnmap'
    capabilities = [ToolCapability.RECON, ToolCapability.NETWORK]
    default_timeout = 60

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        # -d: domain/IP/ASN input, -json: JSON output, -silent: no banner
        args = [self.binary, '-d', target, '-json', '-silent']
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
            asn = obj.get('asn', '')
            org = obj.get('org', '')
            cidrs = obj.get('cidr', [])
            if isinstance(cidrs, str):
                cidrs = [cidrs]
            country = obj.get('country', '')
            for cidr in cidrs:
                results.append(ToolResult(
                    tool_name=self.name,
                    category='network-range',
                    title=f'ASN Range: {cidr}',
                    description=f'ASN {asn} ({org}) - {country}: {cidr}',
                    severity=ToolSeverity.INFO,
                    confidence=0.95,
                    evidence=f'ASN={asn} ORG={org} Country={country}',
                    metadata={'asn': asn, 'org': org, 'cidr': cidr, 'country': country},
                ))
        return results


TOOL_CLASS = AsnmapTool
