"""
WSTGInputValidationTester — OWASP WSTG-INPV gap coverage.
Maps to: WSTG-INPV-06 (HTTP Verb Tampering), WSTG-INPV-07 (HTTP Parameter Pollution),
         WSTG-INPV-15 (HTTP Splitting/Smuggling via Headers), WSTG-INPV-16 (HTTP Incoming),
         WSTG-INPV-17 (IMAP/SMTP Injection), WSTG-INPV-18 (Code Injection).

Note: Core injection tests (SQLi, XSS, CMDi, etc.) are covered by dedicated testers.
This tester covers the remaining WSTG-INPV gaps.

Fills input validation testing gaps identified in Phase 46.
"""
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# HTTP verbs to try for verb tampering (WSTG-INPV-06)
ALTERNATIVE_VERBS = ['HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE',
                     'CONNECT', 'TRACE', 'PROPFIND', 'SEARCH']

# Header injection payloads (WSTG-INPV-15) — attempt response splitting
HEADER_INJECTION_PAYLOADS = [
    'test\r\nX-Injected: true',
    'test\r\nSet-Cookie: injected=1',
    'test\nX-Injected: true',
    '%0d%0aX-Injected: true',
    '%0aX-Injected: true',
]

# IMAP/SMTP injection payloads (WSTG-INPV-17)
IMAP_SMTP_PAYLOADS = [
    '")\r\nA1 SELECT INBOX',
    '"\r\nMAIL FROM:<attacker@example.com>',
    '"\r\nRCPT TO:<attacker@example.com>',
    '%0d%0aMAIL FROM:<attacker@example.com>',
    'test%0ABCC:attacker@example.com',
    'test%0D%0ABCC:attacker@example.com',
]


class WSTGInputValidationTester(BaseTester):
    """WSTG-INPV: Input Validation — verb tampering, IMAP/SMTP injection, header splitting."""

    TESTER_NAME = 'WSTG-INPV'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # WSTG-INPV-06: HTTP Verb Tampering
        vuln = self._test_verb_tampering(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-INPV-15/16: HTTP Header Injection via parameters
        if depth in ('medium', 'deep'):
            vulns = self._test_header_injection(page)
            vulnerabilities.extend(vulns)

        # WSTG-INPV-17: IMAP/SMTP Injection (email fields)
        if depth in ('medium', 'deep'):
            vulns = self._test_imap_smtp_injection(page)
            vulnerabilities.extend(vulns)

        # WSTG-INPV-18: Code Injection (server-side expression injection)
        if depth == 'deep':
            vulns = self._test_expression_injection(page)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    # ── WSTG-INPV-06: HTTP Verb Tampering ────────────────────────────────────

    def _test_verb_tampering(self, url: str):
        """
        Test if the application grants access to protected resources
        via unexpected HTTP verbs that bypass access control checks.
        """
        # First check normal GET response
        baseline = self._make_request('GET', url)
        if not baseline:
            return None

        baseline_status = baseline.status_code
        # Only interesting if page is protected (401, 403) or generally accessible
        if baseline_status not in (200, 401, 403):
            return None

        for verb in ALTERNATIVE_VERBS:
            resp = self._make_request(verb, url)
            if not resp:
                continue

            # The key finding: a verb that was 401/403 on GET returns 200
            if baseline_status in (401, 403) and resp.status_code == 200:
                return self._build_vuln(
                    name=f'HTTP Verb Tampering Bypasses Access Control (HTTP {verb})',
                    severity='high',
                    category='WSTG-INPV-06: Testing for HTTP Verb Tampering',
                    description=f'A GET request to this URL returns HTTP {baseline_status} '
                                f'(access denied), but an HTTP {verb} request returns HTTP 200 '
                                f'(access granted). Access control may only be enforced for GET/POST.',
                    impact='Attackers can bypass authentication or authorization controls '
                           'by using an alternative HTTP method.',
                    remediation='Ensure access control is enforced for ALL HTTP methods, not just '
                                'GET/POST. In web frameworks, apply authorization to all verbs or '
                                'restrict allowed methods explicitly.',
                    cwe='CWE-650',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'GET → HTTP {baseline_status}, {verb} → HTTP {resp.status_code}.',
                )
        return None

    # ── WSTG-INPV-15/16: HTTP Header Injection ───────────────────────────────

    def _test_header_injection(self, page) -> list:
        """Test URL/form parameters for HTTP response header injection."""
        found = []

        for param in (getattr(page, 'parameters', []) or []):
            param_name = param if isinstance(param, str) else getattr(param, 'name', str(param))

            for payload in HEADER_INJECTION_PAYLOADS[:3]:  # limit probes
                # Inject via URL parameter
                parsed = urlparse(page.url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                resp = self._make_request('GET', test_url)
                if not resp:
                    continue

                # Check if injected header appeared in response
                if 'X-Injected' in resp.headers or 'injected' in resp.headers.get('Set-Cookie', ''):
                    found.append(self._build_vuln(
                        name=f'HTTP Response Header Injection via Parameter: {param_name}',
                        severity='high',
                        category='WSTG-INPV-15: HTTP Response Splitting',
                        description=f'The parameter "{param_name}" is reflected unsanitized into '
                                    f'an HTTP response header. CRLF injection allows injecting '
                                    f'arbitrary headers or splitting the response.',
                        impact='Response splitting can be used for cache poisoning, XSS via '
                               'injected HTML, cookie injection, or redirecting users.',
                        remediation='Sanitize all user input before including it in HTTP response '
                                    'headers. Remove \\r, \\n, and their URL-encoded variants. '
                                    'Use safe header-setting APIs.',
                        cwe='CWE-113',
                        cvss=7.2,
                        affected_url=test_url,
                        evidence=f'Injected header found in response. Payload: {payload[:100]}',
                    ))
                    break
        return found

    # ── WSTG-INPV-17: IMAP/SMTP Injection ────────────────────────────────────

    def _test_imap_smtp_injection(self, page) -> list:
        """Test email-related form fields for IMAP/SMTP injection."""
        found = []

        for form in (getattr(page, 'forms', None) or []):
            inputs = getattr(form, 'inputs', []) or []
            email_fields = [
                i for i in inputs
                if any(k in (getattr(i, 'name', '') or '').lower()
                       for k in ('email', 'mail', 'to', 'from', 'cc', 'bcc',
                                 'recipient', 'message', 'subject'))
                and getattr(i, 'type', 'text') in ('text', 'email', '')
            ]

            if not email_fields:
                continue

            action = getattr(form, 'action', '') or page.url
            method = (getattr(form, 'method', 'post') or 'post').upper()

            for field in email_fields[:2]:  # limit to 2 email fields
                field_name = getattr(field, 'name', 'email')
                for payload in IMAP_SMTP_PAYLOADS[:3]:
                    data = {field_name: payload}
                    resp = self._make_request(method, action, data=data)
                    if not resp:
                        continue

                    body = (resp.text or '').lower()
                    # Server error or specific mail-related error may indicate injection
                    smtp_errors = [
                        '500 command unrecognized', 'smtp', 'mail server',
                        'sendmail', 'postfix', 'imap command', 'a1 select',
                    ]
                    if any(e in body for e in smtp_errors) and resp.status_code < 500:
                        found.append(self._build_vuln(
                            name=f'Potential IMAP/SMTP Injection via Field: {field_name}',
                            severity='high',
                            category='WSTG-INPV-17: Testing for IMAP/SMTP Injection',
                            description=f'The form field "{field_name}" may be vulnerable to '
                                        f'IMAP/SMTP command injection. The response body contains '
                                        f'mail protocol indicators after payload injection.',
                            impact='Attackers can relay spam, bypass SMTP restrictions, '
                                   'access other users\' mailboxes, or exfiltrate data.',
                            remediation='Validate and sanitize all email-related inputs. '
                                        'Remove or encode CRLF sequences. Use parameterized '
                                        'mail APIs instead of string interpolation.',
                            cwe='CWE-93',
                            cvss=7.6,
                            affected_url=action,
                            evidence=f'Field: {field_name}. Payload: {payload[:80]}. '
                                     f'Response body contained mail server indication.',
                        ))
                        break
        return found

    # ── WSTG-INPV-18: Expression/Code Injection ───────────────────────────────

    def _test_expression_injection(self, page) -> list:
        """
        Test for server-side expression language injection distinct from SSTI.
        Targets EL/SpEL (Java), Pebble, Mako, Velocity template engines.
        """
        found = []
        # EL injection: ${7*7} should evaluate to 49
        payloads = [
            ('${7*7}', '49'),
            ('#{7*7}', '49'),
            ('*{7*7}', '49'),
            ('[[${7*7}]]', '49'),
        ]

        params_src = getattr(page, 'parameters', None) or {}
        param_keys = list(params_src.keys() if isinstance(params_src, dict) else params_src)[:5]
        for param in param_keys:  # limit
            param_name = param if isinstance(param, str) else getattr(param, 'name', str(param))

            for payload, expected in payloads:
                parsed = urlparse(page.url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                resp = self._make_request('GET', test_url)
                if not resp:
                    continue

                if expected in (resp.text or ''):
                    found.append(self._build_vuln(
                        name=f'Server-Side Expression Injection via Parameter: {param_name}',
                        severity='critical',
                        category='WSTG-INPV-18: Code Injection',
                        description=f'The parameter "{param_name}" is vulnerable to expression '
                                    f'language injection. The payload {payload!r} was evaluated '
                                    f'server-side and returned the calculated result "{expected}".',
                        impact='Remote code execution via template/expression language evaluation.',
                        remediation='Never pass user input directly to expression language evaluators. '
                                    'Use context-isolated templates with strict escaping. '
                                    'Disable remote class resolution in EL/SpEL.',
                        cwe='CWE-917',
                        cvss=9.8,
                        affected_url=test_url,
                        evidence=f'Payload {payload!r} → response contained "{expected}".',
                    ))
                    break
        return found
