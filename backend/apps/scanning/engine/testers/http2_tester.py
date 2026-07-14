"""
HTTP2Tester — HTTP/2 protocol-level attack detection.

Tests for: h2c upgrade smuggling, HTTP/2 → HTTP/1.1 downgrade, HPACK
header injection, RST_STREAM abuse, and priority manipulation.
"""
import re
import logging
from urllib.parse import urlparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)


class HTTP2Tester(BaseTester):
    """Test for HTTP/2 protocol-level vulnerabilities."""

    TESTER_NAME = 'HTTP2'

    # HPACK injection payloads
    _HPACK_PAYLOADS = [
        (':method', 'GET\r\nX-Injected: true'),
        (':path', '/ HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /admin'),
        (':authority', 'target.com\r\nHost: evil.com'),
        ('x-custom', 'value\x00hidden'),
    ]

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Shallow: h2c cleartext upgrade detection
        vuln = self._test_h2c_upgrade(page)
        if vuln:
            vulnerabilities.append(vuln)

        # Check HTTP/2 support
        h2_supported = self._detect_http2_support(page)

        if depth in ('medium', 'deep'):
            # h2c smuggling
            vuln = self._test_h2c_smuggling(page)
            if vuln:
                vulnerabilities.append(vuln)

            # HTTP/2 → HTTP/1.1 downgrade issues
            vuln = self._test_downgrade(page)
            if vuln:
                vulnerabilities.append(vuln)

            # HPACK header injection
            hpack_vulns = self._test_hpack_injection(page)
            vulnerabilities.extend(hpack_vulns)

        if depth == 'deep':
            # RST_STREAM abuse detection (DoS vector)
            vuln = self._test_rst_stream_abuse(page, h2_supported)
            if vuln:
                vulnerabilities.append(vuln)

            # Priority injection / tree manipulation
            vuln = self._test_priority_injection(page, h2_supported)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_h2c_upgrade(self, page):
        """Test for HTTP/2 cleartext (h2c) upgrade support."""
        parsed = urlparse(page.url)
        if parsed.scheme == 'https':
            # h2c is only relevant for unencrypted connections
            test_url = page.url.replace('https://', 'http://', 1)
        else:
            test_url = page.url

        # Send upgrade request with h2c token
        headers = {
            'Upgrade': 'h2c',
            'HTTP2-Settings': 'AAMAAABkAARAAAAAAAIAAAAA',
            'Connection': 'Upgrade, HTTP2-Settings',
        }
        resp = self._make_request('GET', test_url, headers=headers)
        if not resp:
            return None

        # Check for 101 Switching Protocols or h2c upgrade
        if resp.status_code == 101:
            return self._build_vuln(
                name='HTTP/2 Cleartext (h2c) Upgrade Supported',
                severity='medium',
                category='HTTP/2 Protocol',
                description='The server accepts h2c (HTTP/2 cleartext) upgrade requests. '
                           'This can be abused to bypass reverse proxies that do not understand '
                           'h2c, enabling request smuggling.',
                impact='h2c upgrade can bypass proxy-level access controls, WAFs, and '
                      'authentication. Attackers can send h2c requests that proxies pass '
                      'through without inspection, accessing internal endpoints.',
                remediation='Disable h2c upgrade support on the backend server. '
                           'Configure the reverse proxy to strip Upgrade: h2c headers. '
                           'Use HTTPS (h2 with ALPN) instead of cleartext h2c.',
                cwe='CWE-444',
                cvss=6.5,
                affected_url=test_url,
                evidence='Server responded with 101 Switching Protocols to h2c upgrade request.',
            )

        # Check if upgrade header is reflected in response
        upgrade_header = (resp.headers.get('Upgrade', '') or '').lower()
        if 'h2c' in upgrade_header:
            return self._build_vuln(
                name='HTTP/2 Cleartext (h2c) Upgrade Available',
                severity='low',
                category='HTTP/2 Protocol',
                description='The server indicates h2c upgrade availability in response headers.',
                impact='h2c support may enable proxy bypass attacks.',
                remediation='Disable h2c if not required. Use HTTPS with ALPN negotiation.',
                cwe='CWE-444',
                cvss=4.3,
                affected_url=test_url,
                evidence=f'Upgrade response header contains h2c: {upgrade_header}',
            )
        return None

    def _detect_http2_support(self, page):
        """Detect if the server supports HTTP/2."""
        headers = page.headers if hasattr(page, 'headers') else {}
        if not isinstance(headers, dict):
            return False

        # Check for ALPN negotiation indicators
        alt_svc = headers.get('alt-svc', '') or headers.get('Alt-Svc', '') or ''
        if 'h2' in alt_svc or 'h3' in alt_svc:
            return True

        # Check for HTTP/2 specific headers
        if any(k.startswith(':') for k in headers):
            return True

        return False

    def _test_h2c_smuggling(self, page):
        """Test for h2c smuggling via proxy bypass."""
        # Send a request that a proxy might forward with h2c upgrade
        # The proxy forwards the Upgrade header, but doesn't understand h2c
        headers = {
            'Upgrade': 'h2c',
            'HTTP2-Settings': 'AAMAAABkAARAAAAAAAIAAAAA',
            'Connection': 'Upgrade, HTTP2-Settings',
        }

        # Test with typical internal paths that a proxy normally blocks
        internal_paths = ['/admin', '/internal', '/api/internal', '/debug', '/status']
        parsed = urlparse(page.url)
        base_url = f'{parsed.scheme}://{parsed.netloc}'

        for path in internal_paths:
            test_url = base_url + path
            resp = self._make_request('GET', test_url, headers=headers)
            if not resp:
                continue

            # If we get a 200 with h2c upgrade header while direct access is blocked
            normal_resp = self._make_request('GET', test_url)
            if normal_resp and normal_resp.status_code in (401, 403, 404) and \
               resp.status_code == 200:
                return self._build_vuln(
                    name='h2c Smuggling — Proxy Bypass',
                    severity='high',
                    category='HTTP/2 Protocol',
                    description=f'The h2c upgrade request to {path} returned 200 while '
                               f'direct access returned {normal_resp.status_code}. This '
                               f'indicates the h2c upgrade bypasses proxy-level access controls.',
                    impact='Attackers can bypass reverse proxy authentication and access '
                          'internal endpoints, admin panels, and debugging interfaces.',
                    remediation='Configure the proxy to reject h2c upgrade requests. '
                               'Strip Upgrade and HTTP2-Settings headers at the proxy level.',
                    cwe='CWE-444',
                    cvss=8.1,
                    affected_url=test_url,
                    evidence=f'h2c request to {path}: HTTP {resp.status_code}\n'
                            f'Direct request to {path}: HTTP {normal_resp.status_code}',
                )
        return None

    def _test_downgrade(self, page):
        """Test for HTTP/2 to HTTP/1.1 request smuggling via downgrade."""
        urlparse(page.url)

        # Detect downgrade by inspecting response behaviour
        # If a proxy speaks h2 but backend speaks h1.1, CL/TE desync is possible
        smuggle_headers = {
            'Transfer-Encoding': 'chunked',
            'Content-Length': '0',
        }
        resp = self._make_request('POST', page.url, headers=smuggle_headers,
                                  data='0\r\n\r\n')
        if not resp:
            return None

        # If server processes both headers (potential CL-TE desync)
        resp2 = self._make_request('GET', page.url)
        if resp2 and resp2.status_code != resp.status_code:
            # Potential desync - the second request was affected by the first
            return self._build_vuln(
                name='HTTP/2 Downgrade Request Smuggling Indicator',
                severity='medium',
                category='HTTP/2 Protocol',
                description='CL/TE header desync detected during HTTP/2→HTTP/1.1 downgrade. '
                           'The server processes both Content-Length and Transfer-Encoding, '
                           'which may allow request smuggling when behind an h2-to-h1 proxy.',
                impact='Request smuggling via downgrade can bypass security controls, '
                      'poison caches, and hijack other users\' requests.',
                remediation='Ensure the backend rejects requests with both Content-Length '
                           'and Transfer-Encoding. Normalize protocol version at proxy level.',
                cwe='CWE-444',
                cvss=7.5,
                affected_url=page.url,
                evidence=f'POST with CL/TE: HTTP {resp.status_code}\n'
                        f'Follow-up GET: HTTP {resp2.status_code}',
            )
        return None

    def _test_hpack_injection(self, page):
        """Test for HPACK header injection / smuggling."""
        vulns = []
        for pseudo_header, payload in self._HPACK_PAYLOADS:
            # We can't directly inject h2 pseudo-headers via HTTP/1.1 requests,
            # but we can test if the backend processes injected CRLF in header values
            if '\r\n' in payload:
                header_name = 'X-H2-Test' if pseudo_header.startswith(':') else pseudo_header
                resp = self._make_request('GET', page.url,
                                         headers={header_name: payload.replace('\r\n', ' ')})
                if not resp:
                    continue

                # Also test actual CRLF injection via the raw value
                resp_crlf = self._make_request('GET', page.url,
                                               headers={header_name: payload})
                if not resp_crlf:
                    continue

                # If the response contains the injected header content, CRLF worked
                if 'X-Injected' in resp_crlf.text or 'evil.com' in resp_crlf.text:
                    vulns.append(self._build_vuln(
                        name=f'Header Injection via {pseudo_header}',
                        severity='high',
                        category='HTTP/2 Protocol',
                        description=f'CRLF/header injection detected via "{pseudo_header}" '
                                   f'header. Injected content appears in the response.',
                        impact='Header injection enables response splitting, '
                              'cache poisoning, and XSS.',
                        remediation='Reject header values containing CRLF, null bytes, '
                                   'or other control characters.',
                        cwe='CWE-113',
                        cvss=7.5,
                        affected_url=page.url,
                        evidence=f'Header: {pseudo_header}\nInjected content in response.',
                    ))
                    break

            elif '\x00' in payload:
                header_name = 'X-H2-Null'
                resp = self._make_request('GET', page.url,
                                         headers={header_name: payload})
                if resp and 'hidden' in (resp.text or ''):
                    vulns.append(self._build_vuln(
                        name='Null Byte Header Injection',
                        severity='medium',
                        category='HTTP/2 Protocol',
                        description='Null byte in header values is processed by the server. '
                                   'After h2→h1 downgrade, this can hide header content.',
                        impact='Null byte injection can bypass WAF header validation.',
                        remediation='Strip null bytes from all header values.',
                        cwe='CWE-113',
                        cvss=5.3,
                        affected_url=page.url,
                        evidence=f'Header: {header_name}\nNull byte was processed.',
                    ))
        return vulns

    def _test_rst_stream_abuse(self, page, h2_supported):
        """
        Detect potential RST_STREAM / rapid-reset DoS vulnerability.
        CVE-2023-44487.
        """
        # We can't send h2 RST_STREAM frames via HTTP/1.1, but we can detect
        # if the server is vulnerable by checking for HTTP/2 support + server version
        headers = page.headers if hasattr(page, 'headers') else {}
        if not isinstance(headers, dict):
            return None

        server_header = headers.get('server', '') or headers.get('Server', '') or ''

        # Known vulnerable versions (CVE-2023-44487 rapid reset)
        vuln_patterns = [
            (r'nginx/1\.(2[0-4]|[0-1]\d)', 'nginx < 1.25.3'),
            (r'Apache/2\.4\.(5[0-7])', 'Apache < 2.4.58'),
            (r'envoy/1\.2[0-7]', 'Envoy < 1.28'),
        ]

        for pattern, desc in vuln_patterns:
            if re.search(pattern, server_header, re.IGNORECASE):
                return self._build_vuln(
                    name='HTTP/2 Rapid Reset DoS (CVE-2023-44487)',
                    severity='high',
                    category='HTTP/2 Protocol',
                    description=f'Server version ({desc}) is potentially vulnerable to '
                               f'HTTP/2 Rapid Reset attack (CVE-2023-44487). An attacker '
                               f'can send streams and immediately reset them, causing '
                               f'server resource exhaustion.',
                    impact='Denial of Service. The server can be overwhelmed by rapid '
                          'stream creation and RST_STREAM frames, consuming CPU and memory.',
                    remediation=f'Update the server software ({desc} is vulnerable). '
                               'Apply rate limiting on RST_STREAM frames. '
                               'Configure max_concurrent_streams to a conservative value.',
                    cwe='CWE-400',
                    cvss=7.5,
                    affected_url=page.url,
                    evidence=f'Server header: {server_header}\n'
                            f'Potentially vulnerable: {desc}',
                )

        # Also check if h2 is supported and SETTINGS max_concurrent_streams is unrestricted
        if h2_supported:
            alt_svc = headers.get('alt-svc', '') or headers.get('Alt-Svc', '') or ''
            if 'h2' in alt_svc:
                return self._build_vuln(
                    name='HTTP/2 RST_STREAM Abuse Risk',
                    severity='info',
                    category='HTTP/2 Protocol',
                    description='HTTP/2 is supported. Ensure RST_STREAM rate limiting is '
                               'configured to prevent CVE-2023-44487 rapid reset attacks.',
                    impact='Without RST_STREAM limits, the server may be vulnerable to DoS.',
                    remediation='Configure max_concurrent_streams and RST_STREAM rate limits.',
                    cwe='CWE-400',
                    cvss=0,
                    affected_url=page.url,
                    evidence=f'Alt-Svc: {alt_svc}',
                )
        return None

    def _test_priority_injection(self, page, h2_supported):
        """
        Test for HTTP/2 priority tree manipulation.
        Attackers can manipulate stream priorities to starve legitimate requests.
        """
        # Priority manipulation is h2-frame level — we detect configuration indicators
        headers = page.headers if hasattr(page, 'headers') else {}
        if not isinstance(headers, dict):
            return None

        # If server sends priority-related headers, it may be susceptible
        priority_headers = ['priority', 'x-priority', 'x-stream-weight']
        for ph in priority_headers:
            val = headers.get(ph, '') or ''
            if val:
                return self._build_vuln(
                    name='HTTP/2 Priority Headers Detected',
                    severity='info',
                    category='HTTP/2 Protocol',
                    description=f'Server exposes priority information via "{ph}" header. '
                               f'HTTP/2 stream priority can be manipulated to perform '
                               f'resource starvation on co-hosted applications.',
                    impact='An attacker sharing the same HTTP/2 connection can manipulate '
                          'stream dependency trees to deprioritize other users\' requests.',
                    remediation='Do not expose priority information in response headers. '
                               'Implement fair queuing at the server level.',
                    cwe='CWE-400',
                    cvss=0,
                    affected_url=page.url,
                    evidence=f'Header: {ph}: {val}',
                )

        # Check if server echoes back priority settings (injection via header)
        resp = self._make_request('GET', page.url,
                                  headers={'Priority': 'u=0, i'})
        if resp:
            resp_priority = resp.headers.get('priority', '') or ''
            if 'u=0' in resp_priority:
                return self._build_vuln(
                    name='HTTP/2 Priority Reflection',
                    severity='low',
                    category='HTTP/2 Protocol',
                    description='Server reflects client-sent Priority header values. '
                               'This may allow priority tree manipulation.',
                    impact='Priority manipulation could be used for resource starvation.',
                    remediation='Do not reflect client priority values.',
                    cwe='CWE-400',
                    cvss=3.1,
                    affected_url=page.url,
                    evidence='Client Priority "u=0, i" reflected in response.',
                )
        return None
