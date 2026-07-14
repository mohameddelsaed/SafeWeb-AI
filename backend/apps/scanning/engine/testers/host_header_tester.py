"""
HostHeaderTester — Host Header Injection detection.
OWASP A05:2021 — Security Misconfiguration.

Tests for: host header injection, password reset poisoning, cache poisoning
via host header, X-Forwarded-Host abuse, and web cache deception.
"""
import logging
from urllib.parse import urlparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)


class HostHeaderTester(BaseTester):
    """Test for Host Header Injection vulnerabilities."""

    TESTER_NAME = 'Host Header'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Test basic host header injection
        vuln = self._test_host_injection(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Test X-Forwarded-Host injection
        vuln = self._test_forwarded_host(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Test duplicate host headers
        if depth in ('medium', 'deep'):
            vuln = self._test_duplicate_host(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # Test absolute URL override
        if depth == 'deep':
            vuln = self._test_absolute_url(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_host_injection(self, url):
        """Test if the application reflects a modified Host header."""
        evil_host = 'evil-attacker.com'
        headers = {'Host': evil_host}
        response = self._make_request('GET', url, headers=headers)
        if not response:
            return None

        body = response.text.lower()
        if evil_host in body:
            return self._build_vuln(
                name='Host Header Injection',
                severity='high',
                category='Host Header Injection',
                description='The application reflects the Host header value in its response. '
                           'This can be exploited for password reset poisoning, cache poisoning, '
                           'and phishing attacks.',
                impact='Attackers can poison password reset links to steal tokens, '
                      'poison web caches to serve malicious content, or redirect users.',
                remediation='Validate the Host header against a whitelist of allowed domains. '
                           'Use a SERVER_NAME directive instead of relying on the Host header. '
                           'Ignore X-Forwarded-Host in production.',
                cwe='CWE-644',
                cvss=6.1,
                affected_url=url,
                evidence=f'Injected Host header: {evil_host}\nReflected in response body.',
            )

        # Check headers for reflection
        for header_name, header_value in response.headers.items():
            if evil_host in header_value.lower():
                return self._build_vuln(
                    name='Host Header Injection (Response Headers)',
                    severity='high',
                    category='Host Header Injection',
                    description=f'The injected Host header value was reflected in response header: {header_name}.',
                    impact='Can be exploited for password reset poisoning and open redirect.',
                    remediation='Validate the Host header against allowed values.',
                    cwe='CWE-644',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'Injected Host: {evil_host}\nReflected in header: {header_name}: {header_value}',
                )
        return None

    def _test_forwarded_host(self, url):
        """Test X-Forwarded-Host header injection."""
        evil_host = 'evil-attacker.com'
        forwarded_headers = [
            ('X-Forwarded-Host', evil_host),
            ('X-Host', evil_host),
            ('X-Forwarded-Server', evil_host),
            ('X-Original-URL', f'http://{evil_host}/'),
        ]

        for header_name, header_value in forwarded_headers:
            headers = {header_name: header_value}
            response = self._make_request('GET', url, headers=headers)
            if not response:
                continue

            if evil_host in response.text.lower():
                return self._build_vuln(
                    name=f'Host Injection via {header_name}',
                    severity='high',
                    category='Host Header Injection',
                    description=f'The application trusts the {header_name} header, reflecting '
                               f'the attacker-controlled value in the response.',
                    impact='Password reset links, canonical URLs, and cached content '
                          'can be poisoned to point to attacker-controlled domains.',
                    remediation=f'Ignore or validate the {header_name} header. '
                               f'Configure reverse proxies to strip/override this header.',
                    cwe='CWE-644',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'{header_name}: {header_value} → reflected in response.',
                )

            # Also check response headers
            for rh_name, rh_value in response.headers.items():
                if evil_host in rh_value.lower():
                    return self._build_vuln(
                        name=f'Host Injection via {header_name}',
                        severity='high',
                        category='Host Header Injection',
                        description=f'The {header_name} header value was reflected in response header {rh_name}.',
                        impact='Exploitable for cache poisoning and redirect attacks.',
                        remediation=f'Validate the {header_name} header server-side.',
                        cwe='CWE-644',
                        cvss=6.1,
                        affected_url=url,
                        evidence=f'{header_name}: {header_value}\nReflected in {rh_name}: {rh_value}',
                    )
        return None

    def _test_duplicate_host(self, url):
        """Test server behavior with duplicate Host headers."""
        # Send request with malformed host containing the host plus evil domain
        parsed = urlparse(url)
        original_host = parsed.netloc
        evil_host = 'evil-attacker.com'

        # Some servers accept: Host: original, evil
        headers = {'Host': f'{original_host}, {evil_host}'}
        response = self._make_request('GET', url, headers=headers)
        if response and evil_host in response.text.lower():
            return self._build_vuln(
                name='Duplicate Host Header Accepted',
                severity='medium',
                category='Host Header Injection',
                description='The server accepts duplicate Host values and may use the attacker-controlled one.',
                impact='Cache poisoning and password reset poisoning via ambiguous Host header parsing.',
                remediation='Reject requests with multiple Host values. Validate Host against expected value.',
                cwe='CWE-644',
                cvss=5.3,
                affected_url=url,
                evidence=f'Duplicate Host header: {original_host}, {evil_host}',
            )
        return None

    def _test_absolute_url(self, url):
        """Test absolute URL with different Host header."""
        evil_host = 'evil-attacker.com'
        headers = {'Host': evil_host}
        # Some servers process an absolute URL path that overrides Host
        response = self._make_request('GET', url, headers=headers)
        if response and response.status_code == 200 and evil_host in response.text.lower():
            return self._build_vuln(
                name='Host Override via Absolute URL',
                severity='medium',
                category='Host Header Injection',
                description='The server accepts a Host header that differs from the '
                           'actual request target, potentially allowing host spoofing.',
                impact='May enable cache poisoning or URL-based attacks when combined with '
                      'reverse proxy misconfigurations.',
                remediation='Ensure the server validates Host header matches the request target.',
                cwe='CWE-644',
                cvss=5.3,
                affected_url=url,
                evidence=f'Modified Host: {evil_host} reflected with absolute URL.',
            )
        return None
