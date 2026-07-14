"""
CRLFInjectionTester — CRLF Injection / HTTP Response Splitting detection.
OWASP A03:2021 — Injection.

Tests for: header injection, HTTP response splitting, log injection,
and Set-Cookie injection via CRLF sequences.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

CRLF_PAYLOADS = [
    '%0d%0aInjected-Header:true',
    '%0d%0a%0d%0a<html>CRLF</html>',
    '%0aInjected-Header:true',
    '%0dInjected-Header:true',
    '%E5%98%8A%E5%98%8DInjected-Header:true',  # Unicode CRLF
    '\\r\\nInjected-Header:true',
    '\r\nInjected-Header:true',
    '%0d%0aSet-Cookie:crlf=injected',
    '%0d%0aLocation:http://evil.com',
    '%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0aSplit',
]

CRLF_CANARY_HEADER = 'Injected-Header'


class CRLFInjectionTester(BaseTester):
    """Test for CRLF Injection / HTTP Response Splitting."""

    TESTER_NAME = 'CRLF Injection'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        payloads = CRLF_PAYLOADS[:4] if depth == 'shallow' else CRLF_PAYLOADS

        # Test URL parameters
        for param_name in page.parameters:
            vuln = self._test_crlf_param(page.url, param_name, payloads)
            if vuln:
                vulnerabilities.append(vuln)

        # Test redirect parameters specifically
        vuln = self._test_redirect_crlf(page)
        if vuln:
            vulnerabilities.append(vuln)

        # Test path-based CRLF (medium/deep)
        if depth in ('medium', 'deep'):
            vuln = self._test_path_crlf(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_crlf_param(self, url, param_name, payloads):
        """Test URL parameter for CRLF injection."""
        for payload in payloads:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))

            response = self._make_request('GET', test_url, allow_redirects=False)
            if not response:
                continue

            # Check if injected header appears in response headers
            if CRLF_CANARY_HEADER.lower() in {k.lower() for k in response.headers}:
                return self._build_vuln(
                    name=f'CRLF Injection in Parameter: {param_name}',
                    severity='high',
                    category='CRLF Injection',
                    description=f'The parameter "{param_name}" is vulnerable to CRLF injection. '
                               f'Injected CRLF sequences resulted in a custom HTTP response header.',
                    impact='Attackers can inject arbitrary HTTP headers, enabling session fixation '
                          '(via Set-Cookie), XSS (via response splitting), cache poisoning, '
                          'and redirect attacks (via Location header).',
                    remediation='Strip or encode CRLF characters (\\r\\n) from all user input. '
                               'Use framework-provided redirect functions that sanitize URLs.',
                    cwe='CWE-113',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                            f'Injected header "{CRLF_CANARY_HEADER}" appeared in response.',
                )

            # Check for Set-Cookie injection
            if 'crlf=injected' in response.headers.get('Set-Cookie', ''):
                return self._build_vuln(
                    name=f'CRLF Set-Cookie Injection: {param_name}',
                    severity='high',
                    category='CRLF Injection',
                    description=f'CRLF injection in "{param_name}" allows setting arbitrary cookies.',
                    impact='Attackers can inject malicious cookies for session fixation attacks.',
                    remediation='Sanitize all CRLF characters from user input used in HTTP headers.',
                    cwe='CWE-113',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'Injected Set-Cookie header via CRLF in {param_name}.',
                )

            # Check for response splitting (body injection)
            if 'CRLF</html>' in (response.text or '') or 'Split' in (response.text or ''):
                return self._build_vuln(
                    name=f'HTTP Response Splitting: {param_name}',
                    severity='critical',
                    category='CRLF Injection',
                    description=f'The parameter "{param_name}" allows full HTTP response splitting.',
                    impact='Attackers can inject entire HTTP responses, enabling XSS, '
                          'cache poisoning, and phishing.',
                    remediation='Strictly sanitize CRLF sequences in all user input.',
                    cwe='CWE-113',
                    cvss=8.1,
                    affected_url=url,
                    evidence=f'Full response splitting achieved via {param_name}.',
                )

        return None

    def _test_redirect_crlf(self, page):
        """Test redirect parameters for CRLF injection (common vector)."""
        redirect_params = ['redirect', 'next', 'url', 'return', 'return_url',
                           'dest', 'destination', 'redir', 'goto', 'continue']

        for param_name in page.parameters:
            if param_name.lower() not in redirect_params:
                continue

            payload = 'http://example.com%0d%0aInjected-Header:true'
            parsed = urlparse(page.url)
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))

            response = self._make_request('GET', test_url, allow_redirects=False)
            if response:
                response.headers.get('Location', '')
                if CRLF_CANARY_HEADER.lower() in {k.lower() for k in response.headers}:
                    return self._build_vuln(
                        name=f'CRLF Injection in Redirect: {param_name}',
                        severity='high',
                        category='CRLF Injection',
                        description=f'The redirect parameter "{param_name}" is vulnerable to CRLF injection.',
                        impact='Attackers can inject headers into the redirect response.',
                        remediation='Use strict URL validation for redirect parameters. '
                                   'Encode CRLF characters before setting Location header.',
                        cwe='CWE-113',
                        cvss=6.1,
                        affected_url=page.url,
                        evidence=f'CRLF injection in redirect parameter: {param_name}',
                    )
        return None

    def _test_path_crlf(self, url):
        """Test for CRLF injection via URL path."""
        parsed = urlparse(url)
        crlf_path = parsed.path.rstrip('/') + '/%0d%0aInjected-Header:true'
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, crlf_path,
            parsed.params, parsed.query, '',
        ))

        response = self._make_request('GET', test_url, allow_redirects=False)
        if response and CRLF_CANARY_HEADER.lower() in {k.lower() for k in response.headers}:
            return self._build_vuln(
                name='CRLF Injection via URL Path',
                severity='high',
                category='CRLF Injection',
                description='The URL path is vulnerable to CRLF injection, allowing '
                           'header injection directly via the request path.',
                impact='Attackers can inject arbitrary response headers via URL path manipulation.',
                remediation='Normalize and validate URL paths. Strip CRLF sequences.',
                cwe='CWE-113',
                cvss=6.1,
                affected_url=url,
                evidence='CRLF in URL path resulted in injected response header.',
            )
        return None
