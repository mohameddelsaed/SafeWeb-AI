"""Nmap — Network mapper for port scanning, service detection, OS fingerprinting."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class NmapTool(ExternalTool):
    name = 'nmap'
    binary = 'nmap'
    capabilities = [ToolCapability.PORT_SCAN, ToolCapability.NETWORK, ToolCapability.RECON]
    default_timeout = 300

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        scan_type = options.get('scan_type', 'service')
        args = self._build_args(target, scan_type, options)
        raw = self._exec(args)
        return self.parse_output(raw)

    def _build_args(self, target: str, scan_type: str, options: dict) -> list[str]:
        args = [self.binary]
        if scan_type == 'quick':
            args += ['-sV', '--top-ports', '100', '-T4']
        elif scan_type == 'full':
            args += ['-sV', '-sC', '-O', '-p-', '-T3']
        elif scan_type == 'vuln':
            args += ['-sV', '--script', 'vuln', '-T3']
        else:  # service
            args += ['-sV', '-sC', '--top-ports', '1000', '-T4']
        ports = options.get('ports')
        if ports:
            args += ['-p', str(ports)]
        args += ['-oX', '-', target]  # XML to stdout
        return args

    def parse_output(self, raw: str) -> list[ToolResult]:
        if not raw or not raw.strip().startswith('<?xml'):
            return self._parse_text(raw)
        results = []
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return self._parse_text(raw)
        for host in root.findall('.//host'):
            addr_el = host.find('address')
            addr = addr_el.get('addr', '') if addr_el is not None else ''
            for port_el in host.findall('.//port'):
                portid = int(port_el.get('portid', 0))
                protocol = port_el.get('protocol', 'tcp')
                state_el = port_el.find('state')
                state = state_el.get('state', '') if state_el is not None else ''
                if state != 'open':
                    continue
                service_el = port_el.find('service')
                svc_name = service_el.get('name', '') if service_el is not None else ''
                svc_product = service_el.get('product', '') if service_el is not None else ''
                svc_version = service_el.get('version', '') if service_el is not None else ''
                scripts = []
                for script_el in port_el.findall('.//script'):
                    scripts.append({
                        'id': script_el.get('id', ''),
                        'output': script_el.get('output', ''),
                    })
                severity = ToolSeverity.INFO
                vuln_scripts = [s for s in scripts if 'VULNERABLE' in s.get('output', '').upper()]
                if vuln_scripts:
                    severity = ToolSeverity.HIGH
                results.append(ToolResult(
                    tool_name=self.name,
                    category='port',
                    title=f'Open port {portid}/{protocol}: {svc_name}',
                    description=f'{svc_product} {svc_version}'.strip(),
                    severity=severity,
                    confidence=0.95,
                    host=addr,
                    port=portid,
                    evidence='\n'.join(
                        f"  {s['id']}: {s['output'][:200]}" for s in scripts
                    ),
                    metadata={
                        'protocol': protocol,
                        'service': svc_name,
                        'product': svc_product,
                        'version': svc_version,
                        'scripts': scripts,
                    },
                ))
        return results

    def _parse_text(self, raw: str) -> list[ToolResult]:
        """Fallback: parse nmap normal output."""
        results = []
        if not raw:
            return results
        port_re = re.compile(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', re.MULTILINE)
        for m in port_re.finditer(raw):
            portid, proto, svc, detail = m.groups()
            results.append(ToolResult(
                tool_name=self.name,
                category='port',
                title=f'Open port {portid}/{proto}: {svc}',
                description=detail.strip(),
                severity=ToolSeverity.INFO,
                confidence=0.90,
                port=int(portid),
                metadata={'protocol': proto, 'service': svc},
            ))
        return results


TOOL_CLASS = NmapTool
