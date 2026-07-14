"""
CORSTester — Cross-Origin Resource Sharing misconfiguration detection.
OWASP A05:2021 — Security Misconfiguration.

Tests for: wildcard origins, null origin, reflected origin,
credentialed wildcard, subdomain wildcard, and insecure protocols.
"""
import logging
from urllib.parse import urlparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

EVIL_ORIGINS = [
    'https://evil.com',
    'https://attacker.example.com',
    'null',                         # null origin attack
]


class CORSTester(BaseTester):
    """Test for CORS misconfiguration vulnerabilities."""

    TESTER_NAME = 'CORS Misconfiguration'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # 1. Check current CORS headers
        vuln = self._check_existing_cors(page)
        if vuln:
            vulnerabilities.append(vuln)

        # 2. Test reflected origin
        vuln = self._test_reflected_origin(page)
        if vuln:
            vulnerabilities.append(vuln)

        # 3. Test null origin
        vuln = self._test_null_origin(page)
        if vuln:
            vulnerabilities.append(vuln)

        # 4. Test subdomain bypass (medium/deep)
        if depth in ('medium', 'deep'):
            vuln = self._test_subdomain_bypass(page)
            if vuln:
                vulnerabilities.append(vuln)

        # 5. Test protocol downgrade (deep)
        if depth == 'deep':
            vuln = self._test_protocol_downgrade(page)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_existing_cors(self, page) -> object:
        """Check existing CORS headers for misconfigurations."""
        try:
            response = self._make_request('GET', page.url)
        except Exception:
            return None

        if not response:
            return None

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')

        if not acao:
            return None

        # Wildcard with credentials
        if acao == '*' and acac.lower() == 'true':
            return self._build_vuln(
                name='CORS Wildcard with Credentials',
                severity='critical',
                category='CORS Misconfiguration',
                description='The server sets Access-Control-Allow-Origin: * together with '
                           'Access-Control-Allow-Credentials: true. While browsers block this '
                           'combination, some misconfigured proxies or older clients may not.',
                impact='Sensitive data can be read by any origin via cross-origin requests.',
                remediation='Never combine wildcard origin with credentials. '
                           'Use a strict allowlist of trusted origins.',
                cwe='CWE-942',
                cvss=9.1,
                affected_url=page.url,
                evidence=f'Access-Control-Allow-Origin: {acao}\n'
                        f'Access-Control-Allow-Credentials: {acac}',
            )

        # Wildcard origin (without credentials — lower risk)
        if acao == '*':
            return self._build_vuln(
                name='CORS Wildcard Origin',
                severity='low',
                category='CORS Misconfiguration',
                description='The server sets Access-Control-Allow-Origin: *. Any origin can read '
                           'response data (without cookies).',
                impact='Public API data can be consumed by any site. May enable data scraping.',
                remediation='Restrict to specific trusted origins unless the API is intentionally public.',
                cwe='CWE-942',
                cvss=3.7,
                affected_url=page.url,
                evidence='Access-Control-Allow-Origin: *',
            )

        return None

    def _test_reflected_origin(self, page) -> object:
        """Test if the Origin header is reflected back."""
        evil_origin = 'https://evil.com'

        try:
            response = self._make_request(
                'GET', page.url,
                headers={'Origin': evil_origin},
            )
        except Exception:
            return None

        if not response:
            return None

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')

        if evil_origin in acao:
            with_creds = acac.lower() == 'true'
            severity = 'critical' if with_creds else 'high'
            cvss = 9.1 if with_creds else 7.5

            return self._build_vuln(
                name='CORS Origin Reflection',
                severity=severity,
                category='CORS Misconfiguration',
                description=f'The server reflects the Origin header value in '
                           f'Access-Control-Allow-Origin. Any origin, including attacker-controlled '
                           f'domains, is trusted. '
                           f'{"Credentials are also allowed, meaning cookies/auth will be sent." if with_creds else ""}',
                impact='Any website can read authenticated responses from this API, '
                      'leading to data theft and CSRF bypass.',
                remediation='Validate the Origin header against a strict allowlist. '
                           'Never reflect the Origin header directly.',
                cwe='CWE-942',
                cvss=cvss,
                affected_url=page.url,
                evidence=f'Sent Origin: {evil_origin}\n'
                        f'Received Access-Control-Allow-Origin: {acao}\n'
                        f'Access-Control-Allow-Credentials: {acac}',
            )

        return None

    def _test_null_origin(self, page) -> object:
        """Test if null origin is accepted."""
        try:
            response = self._make_request(
                'GET', page.url,
                headers={'Origin': 'null'},
            )
        except Exception:
            return None

        if not response:
            return None

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')

        if acao == 'null':
            with_creds = acac.lower() == 'true'
            severity = 'high' if with_creds else 'medium'
            cvss = 8.1 if with_creds else 5.3

            return self._build_vuln(
                name='CORS Null Origin Accepted',
                severity=severity,
                category='CORS Misconfiguration',
                description='The server accepts requests with Origin: null. Sandboxed iframes, '
                           'data: URIs, and redirected requests send null origin. '
                           f'{"Credentials are allowed." if with_creds else ""}',
                impact='An attacker can use a sandboxed iframe to send requests with null origin '
                      'and read responses, bypassing CORS.',
                remediation='Do not include "null" in the allowed origins list. '
                           'Handle null origin as untrusted.',
                cwe='CWE-942',
                cvss=cvss,
                affected_url=page.url,
                evidence=f'Sent Origin: null\n'
                        f'Received Access-Control-Allow-Origin: {acao}\n'
                        f'Access-Control-Allow-Credentials: {acac}',
            )

        return None

    def _test_subdomain_bypass(self, page) -> object:
        """Test if arbitrary subdomains of the target are trusted."""
        parsed = urlparse(page.url)
        domain = parsed.hostname or ''

        # Try subdomain of same domain
        test_origins = [
            f'https://evil.{domain}',
            f'https://test.evil.{domain}',
            f'https://{domain}.evil.com',
        ]

        for origin in test_origins:
            try:
                response = self._make_request(
                    'GET', page.url,
                    headers={'Origin': origin},
                )
            except Exception:
                continue

            if not response:
                continue

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if origin in acao:
                return self._build_vuln(
                    name='CORS Subdomain Wildcard Bypass',
                    severity='high',
                    category='CORS Misconfiguration',
                    description=f'The server trusts arbitrary subdomains via a regex-based origin '
                               f'check. Origin "{origin}" was accepted.',
                    impact='Attackers who compromise any subdomain (e.g., via XSS) can read '
                          'cross-origin responses from the main application.',
                    remediation='Use an exact origin allowlist instead of regex matching. '
                               'Do not blindly trust all subdomains.',
                    cwe='CWE-942',
                    cvss=7.5,
                    affected_url=page.url,
                    evidence=f'Origin: {origin}\n'
                            f'Access-Control-Allow-Origin: {acao}\n'
                            f'Access-Control-Allow-Credentials: {acac}',
                )

        return None

    def _test_protocol_downgrade(self, page) -> object:
        """Test if HTTP origin is trusted for HTTPS page."""
        parsed = urlparse(page.url)
        if parsed.scheme != 'https':
            return None

        http_origin = f'http://{parsed.hostname}'

        try:
            response = self._make_request(
                'GET', page.url,
                headers={'Origin': http_origin},
            )
        except Exception:
            return None

        if not response:
            return None

        acao = response.headers.get('Access-Control-Allow-Origin', '')

        if http_origin in acao:
            return self._build_vuln(
                name='CORS HTTP Origin Trusted on HTTPS',
                severity='medium',
                category='CORS Misconfiguration',
                description=f'The HTTPS endpoint trusts an HTTP origin ({http_origin}). '
                           f'A man-in-the-middle attacker on the insecure origin can read '
                           f'responses from the secure endpoint.',
                impact='MITM attackers intercepting HTTP traffic can steal cross-origin data '
                      'from the HTTPS endpoint.',
                remediation='Only trust HTTPS origins. Reject origins using the HTTP scheme.',
                cwe='CWE-942',
                cvss=5.3,
                affected_url=page.url,
                evidence=f'Origin: {http_origin}\n'
                        f'Access-Control-Allow-Origin: {acao}',
            )

        return None
