"""
HTTPSmugglingTester — HTTP Request Smuggling detection.
OWASP A05:2021 — Security Misconfiguration.

Tests for: CL.TE, TE.CL, and TE.TE desync vulnerabilities by probing
how the server interprets Content-Length vs Transfer-Encoding.
"""
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)


class HTTPSmugglingTester(BaseTester):
    """Test for HTTP Request Smuggling vulnerabilities."""

    TESTER_NAME = 'HTTP Smuggling'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Test CL.TE smuggling
        vuln = self._test_cl_te(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Test TE.CL smuggling
        if depth in ('medium', 'deep'):
            vuln = self._test_te_cl(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # Test TE.TE (obfuscation)
        if depth == 'deep':
            vuln = self._test_te_te_obfuscation(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # Check for HTTP/2 downgrade issues
        if depth == 'deep':
            vuln = self._check_http2_downgrade(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_cl_te(self, url):
        """Test for CL.TE request smuggling.

        Sends conflicting Content-Length and Transfer-Encoding headers.
        If the front-end uses CL and the back-end uses TE, the back-end
        will interpret the request differently.
        """
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '6',
            'Transfer-Encoding': 'chunked',
        }
        # CL says body is 6 bytes, TE says body is chunked with 0-length chunk
        # If server processes chunked, it reads "0\r\n\r\n" and ignores "G"
        # If front-end uses CL=6, it forwards all 6 bytes
        body = '0\r\n\r\nG'

        try:
            response = self._make_request('POST', url, data=body, headers=headers, timeout=10)
        except Exception:
            return None

        if not response:
            return None

        # A 400 or different status from the smuggled "G" prefix may indicate desync
        if response.status_code in (400, 403, 405):
            # Send another request to check if the smuggled prefix affected it
            response2 = self._make_request('GET', url)
            if response2 and response2.status_code in (400, 405):
                return self._build_vuln(
                    name='Potential CL.TE Request Smuggling',
                    severity='critical',
                    category='HTTP Request Smuggling',
                    description='The server may be vulnerable to CL.TE request smuggling. '
                               'Conflicting Content-Length and Transfer-Encoding headers caused '
                               'a protocol desync.',
                    impact='Attackers can smuggle requests to bypass security controls, '
                          'poison web caches, hijack other users\' requests, and perform '
                          'request-level SSRF.',
                    remediation='Use HTTP/2 end-to-end. Configure the front-end to normalize requests. '
                               'Reject ambiguous requests with both CL and TE headers.',
                    cwe='CWE-444',
                    cvss=9.1,
                    affected_url=url,
                    evidence='CL.TE test: conflicting headers caused protocol desync indicators.',
                )
        return None

    def _test_te_cl(self, url):
        """Test for TE.CL request smuggling."""
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '3',
            'Transfer-Encoding': 'chunked',
        }
        # Front-end uses TE (reads chunked), back-end uses CL (reads 3 bytes)
        body = '1\r\nG\r\n0\r\n\r\n'

        try:
            response = self._make_request('POST', url, data=body, headers=headers, timeout=10)
        except Exception:
            return None

        if not response:
            return None

        if response.status_code in (400, 403, 405, 500):
            return self._build_vuln(
                name='Potential TE.CL Request Smuggling',
                severity='critical',
                category='HTTP Request Smuggling',
                description='The server may be vulnerable to TE.CL request smuggling. '
                           'The server\'s handling of chunked transfer encoding conflicts '
                           'with Content-Length interpretation.',
                impact='Full request smuggling capability: cache poisoning, credential theft, '
                      'request hijacking.',
                remediation='Reject requests with both Content-Length and Transfer-Encoding. '
                           'Normalize requests at the reverse proxy.',
                cwe='CWE-444',
                cvss=9.1,
                affected_url=url,
                evidence='TE.CL test: conflicting CL/TE handling detected.',
            )
        return None

    def _test_te_te_obfuscation(self, url):
        """Test for TE.TE smuggling via obfuscated Transfer-Encoding."""
        obfuscations = [
            'Transfer-Encoding: chunked',
            'Transfer-Encoding : chunked',
            'Transfer-Encoding: xchunked',
            'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
            'Transfer-Encoding:\tchunked',
        ]

        for obf in obfuscations[:3]:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': '6',
            }
            # Add obfuscated TE header
            te_key, te_val = obf.split(': ', 1) if ': ' in obf else ('Transfer-Encoding', obf.split(':', 1)[-1].strip())
            headers[te_key] = te_val

            body = '0\r\n\r\nG'
            try:
                response = self._make_request('POST', url, data=body, headers=headers, timeout=10)
            except Exception:
                continue

            if response and response.status_code in (400, 405, 500):
                return self._build_vuln(
                    name='TE.TE Request Smuggling (Obfuscated)',
                    severity='high',
                    category='HTTP Request Smuggling',
                    description='The server processes obfuscated Transfer-Encoding headers, '
                               'which can lead to request smuggling via TE.TE desync.',
                    impact='Obfuscated TE headers can bypass security controls that only check '
                          'for standard Transfer-Encoding headers.',
                    remediation='Normalize and validate Transfer-Encoding headers. '
                               'Strip or reject malformed TE headers.',
                    cwe='CWE-444',
                    cvss=8.1,
                    affected_url=url,
                    evidence=f'Obfuscated TE: {obf}\nServer returned unexpected status.',
                )
        return None

    def _check_http2_downgrade(self, url):
        """Check if the server downgrades HTTP/2 to HTTP/1.1 (h2c smuggling risk)."""
        # Check for h2c upgrade support
        headers = {
            'Upgrade': 'h2c',
            'HTTP2-Settings': 'AAMAAABkAAQCAAAAAAIAAAAA',
            'Connection': 'Upgrade, HTTP2-Settings',
        }
        response = self._make_request('GET', url, headers=headers)
        if response and response.status_code == 101:
            return self._build_vuln(
                name='HTTP/2 Cleartext Upgrade Supported (h2c)',
                severity='medium',
                category='HTTP Request Smuggling',
                description='The server supports h2c (HTTP/2 over cleartext) upgrades, '
                           'which can be abused for request smuggling in reverse proxy setups.',
                impact='h2c smuggling can bypass front-end security controls and access '
                      'internal-only endpoints.',
                remediation='Disable h2c support. Use HTTP/2 only over TLS (h2).',
                cwe='CWE-444',
                cvss=5.3,
                affected_url=url,
                evidence='Server responded with 101 Switching Protocols for h2c upgrade.',
            )
        return None
