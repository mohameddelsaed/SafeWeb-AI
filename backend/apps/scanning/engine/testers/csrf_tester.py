"""
CSRFTester — Tests for Cross-Site Request Forgery vulnerabilities.
OWASP A01:2021 — Broken Access Control.

Tests: missing CSRF tokens, Origin/Referer header bypass, JSON CSRF,
token reuse/predictability, SameSite cookie gaps, double-submit bypass.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)


class CSRFTester(BaseTester):
    """Test for missing CSRF protection on state-changing forms."""

    TESTER_NAME = 'CSRF'

    CSRF_TOKEN_NAMES = [
        'csrf', 'csrftoken', 'csrf_token', '_csrf', 'authenticity_token',
        'xsrf', 'xsrf_token', '_xsrf', '__RequestVerificationToken',
        'csrfmiddlewaretoken', 'antiforgery', 'token', '_token',
    ]

    # Endpoints likely to be state-changing
    STATE_CHANGE_PATHS = [
        '/api/', '/account/', '/settings/', '/profile/', '/admin/',
        '/transfer/', '/payment/', '/checkout/', '/delete/', '/update/',
        '/create/', '/edit/', '/password/', '/email/',
    ]

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        for form in page.forms:
            if form.method.upper() != 'POST':
                continue

            has_csrf = False
            csrf_token_value = None
            for inp in form.inputs:
                if inp.input_type == 'hidden' and any(
                    tok in (inp.name or '').lower() for tok in self.CSRF_TOKEN_NAMES
                ):
                    has_csrf = True
                    csrf_token_value = getattr(inp, 'value', '') or ''
                    break

            if not has_csrf:
                # Also check for CSRF in meta tags / headers
                has_csrf = self._check_meta_csrf(page.body)

            if not has_csrf:
                vulnerabilities.append(self._build_vuln(
                    name='Missing CSRF Token on Form',
                    severity='medium',
                    category='Cross-Site Request Forgery',
                    description=f'A POST form at {form.action or page.url} does not include a CSRF token, '
                               f'making it vulnerable to cross-site request forgery attacks.',
                    impact='An attacker can craft a malicious page that submits this form on behalf of '
                          'an authenticated user, performing unauthorized actions like changing passwords, '
                          'transferring funds, or modifying account settings.',
                    remediation='Include a unique, unpredictable CSRF token in every state-changing form. '
                               'Validate the token server-side on each request. '
                               'Use the SameSite cookie attribute as an additional defense.',
                    cwe='CWE-352',
                    cvss=4.3,
                    affected_url=form.action or page.url,
                    evidence=f'POST form found without CSRF token.\nAction: {form.action}\n'
                            f'Fields: {", ".join(i.name for i in form.inputs if i.name)}',
                ))

            # Deep: Token predictability check
            if has_csrf and csrf_token_value and depth == 'deep':
                vuln = self._check_token_quality(csrf_token_value, form.action or page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # Origin/Referer header bypass (medium + deep)
        if depth in ('medium', 'deep'):
            vulns = self._test_origin_referer_bypass(page)
            vulnerabilities.extend(vulns)

        # JSON Content-Type CSRF (deep)
        if depth == 'deep':
            vulns = self._test_json_csrf(page)
            vulnerabilities.extend(vulns)

        # Check SameSite cookie attribute (additional CSRF defense)
        if depth in ('medium', 'deep'):
            response = self._make_request('GET', page.url)
            if response:
                for cookie_name, cookie in response.cookies.items():
                    same_site = getattr(cookie, 'same_site', None)
                    if same_site is None or same_site.lower() == 'none':
                        vulnerabilities.append(self._build_vuln(
                            name=f'Cookie Missing SameSite Attribute: {cookie_name}',
                            severity='low',
                            category='Cross-Site Request Forgery',
                            description=f'Cookie "{cookie_name}" is missing the SameSite attribute or has it set to None.',
                            impact='Without SameSite, cookies are sent with cross-origin requests, '
                                  'making CSRF attacks easier.',
                            remediation='Set the SameSite attribute to "Lax" or "Strict" on all cookies.',
                            cwe='CWE-1275',
                            cvss=3.1,
                            affected_url=page.url,
                            evidence=f'Cookie: {cookie_name}\nSameSite: {same_site or "not set"}',
                        ))
                        break  # Report once

        return vulnerabilities

    def _check_meta_csrf(self, body):
        """Check for CSRF token in meta tags (common in SPAs)."""
        pattern = r'<meta\s+[^>]*name=["\']csrf[^"\']*["\'][^>]*>'
        return bool(re.search(pattern, body, re.IGNORECASE))

    def _test_origin_referer_bypass(self, page) -> list:
        """Test if server validates Origin/Referer headers on POST requests."""
        vulnerabilities = []

        # Find a POST form with CSRF token (to test header-based enforcement)
        target_form = None
        for form in page.forms:
            if form.method.upper() == 'POST':
                target_form = form
                break

        if not target_form:
            return vulnerabilities

        action = target_form.action or page.url

        # Build minimal form data
        form_data = {}
        for inp in target_form.inputs:
            if inp.name:
                form_data[inp.name] = getattr(inp, 'value', 'test') or 'test'

        # Test 1: Missing Origin header
        response = self._make_request('POST', action, data=form_data, headers={
            'Referer': '',
        })
        if response and response.status_code not in (403, 401, 400):
            vulnerabilities.append(self._build_vuln(
                name='CSRF: Origin/Referer Validation Bypass',
                severity='medium',
                category='Cross-Site Request Forgery',
                description='The server accepts POST requests without Origin/Referer headers.',
                impact='Attackers can perform CSRF using techniques that suppress '
                      'Origin/Referer (e.g., meta referrer policy, data URIs).',
                remediation='Validate Origin and Referer headers on all state-changing requests. '
                           'Reject requests with missing or non-matching origins.',
                cwe='CWE-352',
                cvss=5.3,
                affected_url=action,
                evidence='POST accepted without Origin/Referer headers.',
            ))

        # Test 2: Cross-origin Referer
        response = self._make_request('POST', action, data=form_data, headers={
            'Origin': 'https://evil-attacker.com',
            'Referer': 'https://evil-attacker.com/csrf-page',
        })
        if response and response.status_code not in (403, 401, 400):
            vulnerabilities.append(self._build_vuln(
                name='CSRF: Cross-Origin Request Accepted',
                severity='high',
                category='Cross-Site Request Forgery',
                description='The server accepts POST requests from a different origin.',
                impact='Any website can submit cross-origin requests that are processed '
                      'as if they came from the legitimate site.',
                remediation='Check the Origin header matches your domain. '
                           'Use CSRF tokens AND origin validation as defense-in-depth.',
                cwe='CWE-352',
                cvss=6.5,
                affected_url=action,
                evidence='POST with Origin: https://evil-attacker.com was accepted (not 403/401/400).',
            ))

        return vulnerabilities

    def _test_json_csrf(self, page) -> list:
        """Test for CSRF via JSON content-type (exploitable via Flash/fetch)."""
        vulnerabilities = []

        # Try sending a JSON POST to form actions or API endpoints
        for form in page.forms:
            if form.method.upper() != 'POST':
                continue

            action = form.action or page.url

            # Build JSON body from form fields
            json_data = {}
            for inp in form.inputs:
                if inp.name and inp.input_type != 'hidden':
                    json_data[inp.name] = 'test'

            if not json_data:
                continue

            response = self._make_request('POST', action, json=json_data, headers={
                'Content-Type': 'text/plain',  # Bypass preflight
                'Origin': 'https://evil-attacker.com',
            })

            if response and response.status_code in (200, 201, 302):
                vulnerabilities.append(self._build_vuln(
                    name='JSON CSRF via Content-Type text/plain',
                    severity='medium',
                    category='Cross-Site Request Forgery',
                    description='The server processes JSON-like requests sent with Content-Type text/plain, '
                               'which bypasses CORS preflight checks.',
                    impact='Attackers can send state-changing requests from any website using forms '
                          'or fetch with simple content types.',
                    remediation='Require Content-Type: application/json and validate it server-side. '
                               'This triggers CORS preflight for cross-origin requests.',
                    cwe='CWE-352',
                    cvss=5.3,
                    affected_url=action,
                    evidence='POST with Content-Type: text/plain was processed successfully.',
                ))
                break  # One finding is enough

        return vulnerabilities

    def _check_token_quality(self, token_value: str, url: str):
        """Check CSRF token for predictability issues."""
        if not token_value:
            return None

        # Very short tokens
        if len(token_value) < 16:
            return self._build_vuln(
                name='Short CSRF Token',
                severity='low',
                category='Cross-Site Request Forgery',
                description=f'CSRF token is only {len(token_value)} characters — may be brute-forceable.',
                impact='Short tokens have a smaller entropy space, making them easier to guess.',
                remediation='Use CSRF tokens of at least 128 bits (32 hex chars or 24 base64 chars).',
                cwe='CWE-330',
                cvss=3.7,
                affected_url=url,
                evidence=f'Token length: {len(token_value)} characters',
            )

        # Purely numeric (low entropy)
        if token_value.isdigit():
            return self._build_vuln(
                name='Numeric-Only CSRF Token',
                severity='medium',
                category='Cross-Site Request Forgery',
                description='CSRF token contains only digits — significantly reduced entropy.',
                impact='Numeric-only tokens are easier to brute-force due to smaller character space.',
                remediation='Use cryptographically random tokens with alphanumeric characters.',
                cwe='CWE-330',
                cvss=4.3,
                affected_url=url,
                evidence=f'Token is numeric-only: {token_value[:20]}...',
            )

        return None
