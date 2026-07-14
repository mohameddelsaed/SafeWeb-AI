"""
LoggingTester — Tests for insufficient logging and monitoring.
OWASP A09:2021 — Security Logging and Monitoring Failures.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)


class LoggingTester(BaseTester):
    """Test for insufficient logging and monitoring issues."""

    TESTER_NAME = 'Logging'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Check for verbose error handling
        vuln = self._test_error_verbosity(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for log injection
        if depth in ('medium', 'deep'):
            vuln = self._test_log_injection(page)
            if vuln:
                vulnerabilities.append(vuln)

        # Check for missing security headers related to reporting
        response = self._make_request('GET', page.url)
        if response:
            vuln = self._check_reporting_headers(response, page.url)
            if vuln:
                vulnerabilities.append(vuln)

            vuln = self._check_error_handling(response, page.url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_error_verbosity(self, url):
        """Test if errors reveal too much information."""
        # Trigger errors with malformed requests
        test_cases = [
            (url + "/'", 'Single quote in URL'),
            (url + '/../../etc/passwd', 'Path traversal attempt'),
            (url + '?id=1 UNION SELECT 1--', 'SQL-like input'),
        ]

        for test_url, description in test_cases:
            response = self._make_request('GET', test_url)
            if not response:
                continue

            body = response.text
            verbose_indicators = [
                'Traceback (most recent call last)',
                'at System.',
                'java.lang.Exception',
                'PHP Fatal error',
                'PHP Warning:',
                'ORA-',
                'SQLSTATE',
                'Microsoft OLE DB',
                'Unhandled Exception',
                'stack trace',
                'File "',
                r'line \d+',
            ]

            for indicator in verbose_indicators:
                if re.search(indicator, body, re.IGNORECASE):
                    return self._build_vuln(
                        name='Verbose Error Messages Expose Internal Details',
                        severity='medium',
                        category='Logging & Monitoring',
                        description='The application returns detailed error messages including stack traces, '
                                   'file paths, or database information when processing malformed input.',
                        impact='Error details help attackers understand the application architecture, '
                              'technology stack, and potential attack vectors.',
                        remediation='Implement custom error pages that show generic messages to users. '
                                   'Log detailed errors server-side only. '
                                   'Disable debug mode in production environments.',
                        cwe='CWE-209',
                        cvss=5.3,
                        affected_url=url,
                        evidence=f'Trigger: {description}\nIndicator: {indicator}',
                    )
        return None

    def _test_log_injection(self, page):
        """Test for log injection vulnerabilities."""
        log_payload = 'test\r\nINFO: Admin logged in from 127.0.0.1\r\n'

        for param_name in page.parameters:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(page.url)
            params = parse_qs(parsed.query)
            params[param_name] = log_payload

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), ''
            ))

            response = self._make_request('GET', test_url)
            if response and response.status_code == 200:
                # If the CRLF characters are reflected, log injection may be possible
                if 'Admin logged in' in response.text:
                    return self._build_vuln(
                        name=f'Log Injection via Parameter: {param_name}',
                        severity='medium',
                        category='Logging & Monitoring',
                        description=f'The parameter "{param_name}" may be vulnerable to log injection '
                                   f'via CRLF characters.',
                        impact='Attackers can inject fake log entries, potentially covering tracks '
                              'or triggering false alerts in monitoring systems.',
                        remediation='Sanitize all user input before logging. '
                                   'Remove or encode CRLF characters (\\r\\n). '
                                   'Use structured logging formats.',
                        cwe='CWE-117',
                        cvss=4.3,
                        affected_url=page.url,
                        evidence=f'Parameter: {param_name}\nCRLF payload reflected in response.',
                    )

        return None

    def _check_reporting_headers(self, response, url):
        """Check for security reporting headers."""
        report_to = response.headers.get('Report-To', '')
        nel = response.headers.get('NEL', '')
        csp_report = response.headers.get('Content-Security-Policy', '')

        missing = []
        if not report_to:
            missing.append('Report-To')
        if not nel:
            missing.append('NEL (Network Error Logging)')
        if csp_report and 'report-uri' not in csp_report and 'report-to' not in csp_report:
            missing.append('CSP report-uri/report-to directive')

        if missing:
            return self._build_vuln(
                name='Missing Security Reporting Headers',
                severity='info',
                category='Logging & Monitoring',
                description=f'Missing security reporting mechanisms: {", ".join(missing)}.',
                impact='Without reporting mechanisms, security violations and errors may go undetected.',
                remediation='Configure Report-To header for centralized error reporting. '
                           'Add report-uri directive to CSP. '
                           'Implement Network Error Logging (NEL).',
                cwe='CWE-778',
                cvss=2.0,
                affected_url=url,
                evidence=f'Missing headers: {", ".join(missing)}',
            )
        return None

    def _check_error_handling(self, response, url):
        """Check for proper error handling setup."""
        # Check custom error page by requesting a known 404
        from urllib.parse import urlparse
        parsed = urlparse(url)
        test_url = f'{parsed.scheme}://{parsed.netloc}/safeweb_ai_nonexistent_test_page_82736'
        resp = self._make_request('GET', test_url)

        if resp and resp.status_code == 200:
            # Soft 404 — not ideal but not critical
            return self._build_vuln(
                name='Soft 404 Response',
                severity='info',
                category='Logging & Monitoring',
                description='The server returns HTTP 200 for non-existent pages instead of 404.',
                impact='Soft 404s can confuse security scanners and monitoring tools, '
                      'and may indicate routing issues.',
                remediation='Return proper HTTP 404 status codes for non-existent resources.',
                cwe='CWE-756',
                cvss=2.0,
                affected_url=test_url,
                evidence='Non-existent page returned HTTP 200.',
            )
        return None
