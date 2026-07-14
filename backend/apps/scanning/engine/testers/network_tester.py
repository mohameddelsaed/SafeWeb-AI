"""
Network Tester — BaseTester wrapper for Phase 34.

Integrates the NetworkScanner (port scanning, service detection, SSL/TLS
deep testing) into the standard tester pipeline.

Depth behaviour:
  - quick : port scan + basic SSL check
  - medium: port scan + SSL check + service detection
  - deep  : port scan + SSL full test + service detection + vulnerability analysis
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)


class NetworkTester(BaseTester):
    TESTER_NAME = 'Network Scanner'

    def test(self, page: dict, depth: str = 'quick', recon_data: dict | None = None) -> list[dict]:
        url = page.get('url', '')
        if not url:
            return []

        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return []

        vulns: list[dict] = []

        from apps.scanning.engine.network import NetworkScanner
        scanner = NetworkScanner(timeout=3.0)

        # ── Port scanning (all depths) ───────────────────────────────────
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # Quick: scan just the page port; medium/deep: common ports
        if depth == 'quick':
            scan_ports = [port]
        else:
            from apps.scanning.engine.network.port_scanner import DEFAULT_PORTS
            scan_ports = DEFAULT_PORTS

        port_results = scanner.scan_ports(host, scan_ports)
        open_ports = [p for p in port_results if p.get('state') == 'open']

        # Flag unusual open ports
        for p in open_ports:
            if p['port'] in (21, 23, 25, 135, 139, 445, 3389):
                vulns.append(self._risky_port_vuln(url, host, p))

        # ── SSL/TLS checks (all depths) ─────────────────────────────────
        ssl_port = 443
        has_ssl = any(p['port'] in (443, 8443) for p in open_ports) or parsed.scheme == 'https'

        if has_ssl:
            ssl_result = scanner.test_ssl(host, ssl_port)

            # Deprecated protocols
            for proto in ssl_result.get('protocol_versions', []):
                if proto.get('supported') and proto.get('deprecated'):
                    vulns.append(self._deprecated_proto_vuln(url, host, proto))

            # Certificate issues
            cert = ssl_result.get('certificate', {})
            if cert.get('self_signed'):
                vulns.append(self._cert_vuln(url, host, 'Self-Signed Certificate',
                             'The server uses a self-signed certificate.', 'medium'))
            if cert.get('days_until_expiry') is not None and cert['days_until_expiry'] < 0:
                vulns.append(self._cert_vuln(url, host, 'Expired Certificate',
                             'The server certificate has expired.', 'high'))
            elif cert.get('days_until_expiry') is not None and cert['days_until_expiry'] < 30:
                vulns.append(self._cert_vuln(url, host, 'Certificate Expiring Soon',
                             f"Certificate expires in {cert['days_until_expiry']} days.", 'low'))
            if cert.get('errors') and not cert.get('hostname_match'):
                vulns.append(self._cert_vuln(url, host, 'Certificate Hostname Mismatch',
                             'The certificate CN/SAN does not match the hostname.', 'high'))

            # Known vulnerabilities (deep only for full vuln scan)
            if depth == 'deep':
                for v in ssl_result.get('vulnerabilities', []):
                    vulns.append(self._ssl_vuln(url, host, v))

            # Weak ciphers
            ciphers = ssl_result.get('ciphers', {})
            if ciphers.get('has_weak_ciphers'):
                vulns.append(self._weak_cipher_vuln(url, host, ciphers.get('weak', [])))

            # HSTS
            hsts = ssl_result.get('hsts', {})
            if not hsts.get('enabled'):
                vulns.append(self._hsts_vuln(url, host))

        # ── Service detection (medium + deep) ────────────────────────────
        if depth in ('medium', 'deep') and open_ports:
            service_findings = scanner.test_services(host, open_ports)
            for f in service_findings:
                vulns.append(self._service_vuln(url, host, f))

        return vulns

    # ── Vulnerability builders ────────────────────────────────────────────

    def _risky_port_vuln(self, url: str, host: str, port_info: dict) -> dict:
        return self._build_vuln(
            name=f"Risky Open Port: {port_info['port']}/{port_info.get('service', 'unknown')}",
            severity='medium',
            category='network_port',
            description=(
                f"Port {port_info['port']} ({port_info.get('service', 'unknown')}) "
                f"is open on {host}. This service is commonly targeted by attackers."
            ),
            impact='Open risky ports increase the attack surface and may expose sensitive services.',
            remediation='Close unnecessary ports or restrict access via firewall rules.',
            cwe='CWE-200',
            cvss=0,
            affected_url=url,
            evidence=f"Port {port_info['port']} open, service={port_info.get('service', '')}, banner={port_info.get('banner', '')}",
        )

    def _deprecated_proto_vuln(self, url: str, host: str, proto: dict) -> dict:
        return self._build_vuln(
            name=f"Deprecated Protocol: {proto['protocol']}",
            severity='high',
            category='network_ssl',
            description=(
                f"The server {host} supports deprecated protocol {proto['protocol']}. "
                'Deprecated protocols have known vulnerabilities.'
            ),
            impact='Use of deprecated TLS/SSL protocols enables attacks like POODLE, BEAST, and DROWN.',
            remediation=f"Disable {proto['protocol']} and enable only TLS 1.2 and TLS 1.3.",
            cwe='CWE-326',
            cvss=0,
            affected_url=url,
            evidence=f"{proto['protocol']} is supported and deprecated",
        )

    def _cert_vuln(self, url: str, host: str, name: str, desc: str, severity: str) -> dict:
        return self._build_vuln(
            name=name,
            severity=severity,
            category='network_ssl',
            description=f"{desc} Host: {host}.",
            impact='Certificate issues undermine TLS trust and can enable MitM attacks.',
            remediation='Use a valid certificate from a trusted CA, ensure hostname matches, and renew before expiry.',
            cwe='CWE-295',
            cvss=0,
            affected_url=url,
            evidence=f"Certificate issue on {host}: {name}",
        )

    def _ssl_vuln(self, url: str, host: str, vuln: dict) -> dict:
        return self._build_vuln(
            name=f"SSL Vulnerability: {vuln.get('name', 'Unknown')}",
            severity=vuln.get('severity', 'medium'),
            category='network_ssl',
            description=f"{vuln.get('info', '')} CVE: {vuln.get('cve', 'N/A')}.",
            impact='SSL/TLS vulnerabilities can allow decryption of traffic or MitM attacks.',
            remediation='Update TLS configuration, disable vulnerable protocols and ciphers.',
            cwe='CWE-326',
            cvss=0,
            affected_url=url,
            evidence=f"{vuln.get('name', '')}: {vuln.get('info', '')}",
        )

    def _weak_cipher_vuln(self, url: str, host: str, weak: list) -> dict:
        return self._build_vuln(
            name='Weak TLS Cipher Suites',
            severity='medium',
            category='network_ssl',
            description=f"The server accepts weak cipher suites: {', '.join(weak[:5])}.",
            impact='Weak ciphers can be broken, exposing encrypted communications.',
            remediation='Disable weak ciphers (RC4, DES, NULL, EXPORT, MD5) and use only strong cipher suites.',
            cwe='CWE-326',
            cvss=0,
            affected_url=url,
            evidence=f"Weak ciphers on {host}: {', '.join(weak[:5])}",
        )

    def _hsts_vuln(self, url: str, host: str) -> dict:
        return self._build_vuln(
            name='Missing HSTS Header',
            severity='low',
            category='network_ssl',
            description=f"The server {host} does not set the Strict-Transport-Security header.",
            impact='Without HSTS users can be downgraded to HTTP, enabling MitM attacks.',
            remediation='Add Strict-Transport-Security header with max-age >= 31536000 and includeSubDomains.',
            cwe='CWE-319',
            cvss=0,
            affected_url=url,
            evidence=f"HSTS not enabled on {host}",
        )

    def _service_vuln(self, url: str, host: str, finding: dict) -> dict:
        return self._build_vuln(
            name=finding.get('title', 'Service Issue'),
            severity=finding.get('severity', 'medium'),
            category='network_service',
            description=finding.get('description', ''),
            impact='Exposed or misconfigured services can lead to unauthorized access or data leakage.',
            remediation='Restrict access, enable authentication, or disable unnecessary services.',
            cwe='CWE-284',
            cvss=0,
            affected_url=url,
            evidence=finding.get('evidence', ''),
        )
