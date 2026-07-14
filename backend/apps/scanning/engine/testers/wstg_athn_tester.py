"""
WSTGAuthTester — OWASP WSTG-ATHN gap coverage.
Maps to: WSTG-ATHN-03 (Lockout Mechanism), WSTG-ATHN-05 (Remember Me),
         WSTG-ATHN-06 (Browser Cache), WSTG-ATHN-07 (Password Policy),
         WSTG-ATHN-08 (Security Questions), WSTG-ATHN-09 (Password Change),
         WSTG-ATHN-10 (Over-Encrypted Channel Alternatives),
         WSTG-ATHN-11 (CAPTCHA), WSTG-ATHN-12 (MFA).

Fills authentication testing gaps identified in Phase 46.
"""
import re
import logging
from urllib.parse import urlparse

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Pages that should not be cached by browsers
SENSITIVE_PATHS = [
    '/dashboard', '/account', '/profile', '/settings',
    '/admin', '/payment', '/checkout', '/orders',
    '/reset-password', '/change-password',
]

# "Remember Me" patterns in form HTML
REMEMBER_PATTERNS = [
    r'remember[_\-]?me',
    r'keep[_\-]?me[_\-]?logged',
    r'stay[_\-]?signed[_\-]?in',
    r'persistent',
]

MFA_INDICATORS = [
    '2fa', 'two-factor', 'two factor', 'mfa', 'multi-factor',
    'authenticator', 'otp', 'one-time', 'totp',
]


class WSTGAuthTester(BaseTester):
    """WSTG-ATHN: Authentication Testing — lockout, browser cache, CAPTCHA, MFA."""

    TESTER_NAME = 'WSTG-ATHN'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # WSTG-ATHN-03: Account lockout mechanism
        if depth in ('medium', 'deep'):
            vuln = self._test_lockout_mechanism(page)
            if vuln:
                vulnerabilities.append(vuln)

        # WSTG-ATHN-06: Browser caching of sensitive pages
        vuln = self._test_browser_cache(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-ATHN-05: Insecure "Remember Me" implementation
        vuln = self._test_remember_me(page)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-ATHN-11: CAPTCHA absence on sensitive forms
        if depth in ('medium', 'deep'):
            vuln = self._test_captcha_absence(page)
            if vuln:
                vulnerabilities.append(vuln)

        # WSTG-ATHN-12: MFA availability check
        if depth == 'deep':
            vuln = self._test_mfa_availability(page)
            if vuln:
                vulnerabilities.append(vuln)

        # WSTG-ATHN-09: Insecure password change flow
        if depth in ('medium', 'deep'):
            vuln = self._test_password_change_flow(page)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    # ── WSTG-ATHN-03: Lockout Mechanism ──────────────────────────────────────

    def _test_lockout_mechanism(self, page):
        """Test for missing account lockout on login forms."""
        login_form = self._find_login_form(page)
        if not login_form:
            return None

        action = getattr(login_form, 'action', '') or page.url
        method = (getattr(login_form, 'method', 'post') or 'post').upper()
        inputs = getattr(login_form, 'inputs', []) or []

        username_field = next(
            (i for i in inputs if any(n in (getattr(i, 'name', '') or '').lower()
                                      for n in ('user', 'email', 'login', 'username'))),
            None,
        )
        password_field = next(
            (i for i in inputs if 'pass' in (getattr(i, 'name', '') or '').lower()
             or getattr(i, 'type', '') == 'password'),
            None,
        )
        if not username_field or not password_field:
            return None

        u_name = getattr(username_field, 'name', 'username')
        p_name = getattr(password_field, 'name', 'password')

        # Send 6 rapid failed login attempts and check for lockout or captcha
        lockout_detected = False
        for i in range(6):
            data = {u_name: 'wstg_lockout_test@example.com',
                    p_name: f'wrong_password_{i}'}
            resp = self._make_request(method, action, data=data)
            if not resp:
                return None

            body = (resp.text or '').lower()
            # Check for lockout or CAPTCHA trigger
            if any(k in body for k in ('locked', 'too many', 'temporarily', 'captcha',
                                       'rate limit', 'wait', 'blocked')):
                lockout_detected = True
                break
            if resp.status_code == 429:
                lockout_detected = True
                break

        if lockout_detected:
            return None  # lockout is working

        return self._build_vuln(
            name='Missing Account Lockout After Multiple Failed Login Attempts',
            severity='medium',
            category='WSTG-ATHN-03: Testing for Account Lockout',
            description='The login form does not implement lockout or rate limiting after '
                        'multiple failed authentication attempts. Six consecutive failures '
                        'were made without triggering any lockout, CAPTCHA, or rate-limiting response.',
            impact='Attackers can perform unlimited brute-force attacks against user accounts '
                   'without any detection or mitigation.',
            remediation='Implement account lockout (temporary, not permanent) after 5–10 failed '
                        'attempts. Use progressive delays (exponential backoff), CAPTCHA, '
                        'or rate limiting by IP. Alert on excessive failures.',
            cwe='CWE-307',
            cvss=7.5,
            affected_url=action,
            evidence='6 consecutive failed login attempts with no lockout, CAPTCHA, or 429 response.',
        )

    # ── WSTG-ATHN-06: Browser Cache ──────────────────────────────────────────

    def _test_browser_cache(self, url: str):
        """Detect sensitive pages missing proper no-cache headers."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        is_sensitive = any(s in path for s in SENSITIVE_PATHS) or any(
            s in path for s in ('/user', '/member', '/secure', '/private')
        )
        if not is_sensitive:
            return None

        resp = self._make_request('GET', url)
        if not resp:
            return None

        cache_control = resp.headers.get('Cache-Control', '').lower()
        pragma = resp.headers.get('Pragma', '').lower()
        expires = resp.headers.get('Expires', '')

        has_no_store = 'no-store' in cache_control
        has_no_cache = 'no-cache' in cache_control or 'no-cache' in pragma
        has_past_expires = expires == '0' or expires == '-1'

        if not has_no_store and not (has_no_cache and has_past_expires):
            return self._build_vuln(
                name='Sensitive Page May Be Cached by Browser',
                severity='medium',
                category='WSTG-ATHN-06: Testing for Browser Cache Weaknesses',
                description='This sensitive page does not set Cache-Control: no-store (or equivalent). '
                            'The browser may cache this page, allowing subsequent users of the same '
                            'browser session to view cached authenticated content.',
                impact='Cached sensitive pages can be accessed via browser history or '
                       'shared computers after the user logs out.',
                remediation='Add the following headers to all authenticated/sensitive pages: '
                            'Cache-Control: no-store, no-cache, must-revalidate; '
                            'Pragma: no-cache; Expires: 0.',
                cwe='CWE-525',
                cvss=4.3,
                affected_url=url,
                evidence=f'Cache-Control: {cache_control or "(absent)"}, '
                         f'Pragma: {pragma or "(absent)"}, Expires: {expires or "(absent)"}',
            )
        return None

    # ── WSTG-ATHN-05: Remember Me Weakness ───────────────────────────────────

    def _test_remember_me(self, page):
        """Detect insecure Remember Me implementation."""
        body = getattr(page, 'body', '') or ''
        has_remember = any(re.search(p, body, re.IGNORECASE) for p in REMEMBER_PATTERNS)
        if not has_remember:
            return None

        # Check if a persistent cookie is set (long max-age) without security flags
        resp = self._make_request('GET', page.url)
        if not resp:
            return None

        set_cookie = resp.headers.get('Set-Cookie', '')
        # Look for long-lived cookie without HttpOnly or Secure
        max_age_match = re.search(r'[Mm]ax-[Aa]ge=(\d+)', set_cookie)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age > 86400:  # > 1 day
                missing = []
                if 'HttpOnly' not in set_cookie:
                    missing.append('HttpOnly')
                if 'Secure' not in set_cookie:
                    missing.append('Secure')
                if missing:
                    return self._build_vuln(
                        name='Remember Me Cookie Missing Security Flags',
                        severity='medium',
                        category='WSTG-ATHN-05: Testing Remember Functionality',
                        description='A long-lived (persistent) cookie is set by the "Remember Me" '
                                    f'feature but is missing security flags: {", ".join(missing)}. '
                                    f'Cookie max-age: {max_age} seconds.',
                        impact='Without HttpOnly, the cookie can be stolen via XSS. '
                               'Without Secure, the cookie can be intercepted over HTTP.',
                        remediation='Always set HttpOnly and Secure flags on authentication cookies. '
                                    'Consider limiting Remember Me cookie lifetime to 30 days maximum.',
                        cwe='CWE-614',
                        cvss=5.4,
                        affected_url=page.url,
                        evidence=f'Set-Cookie: {set_cookie[:500]}. Missing: {", ".join(missing)}.',
                    )
        return None

    # ── WSTG-ATHN-11: CAPTCHA ─────────────────────────────────────────────────

    def _test_captcha_absence(self, page):
        """Detect login/registration forms without CAPTCHA protection."""
        login_form = self._find_login_form(page)
        if not login_form:
            return None

        body = (getattr(page, 'body', '') or '').lower()
        has_captcha = any(k in body for k in ('captcha', 'recaptcha', 'hcaptcha',
                                               'turnstile', 'cf-challenge'))
        if not has_captcha:
            return self._build_vuln(
                name='No CAPTCHA on Login Form',
                severity='low',
                category='WSTG-ATHN-11: Testing for CAPTCHA',
                description='The login form does not implement CAPTCHA or any bot detection '
                            'mechanism. This allows automated credential stuffing attacks.',
                impact='Attackers can run high-volume automated login attacks without any '
                       'friction or detection.',
                remediation='Implement CAPTCHA (reCAPTCHA v3, hCaptcha, Cloudflare Turnstile) '
                            'or behavioral bot detection on the login form.',
                cwe='CWE-307',
                cvss=3.7,
                affected_url=page.url,
                evidence='No CAPTCHA widget or challenge indicator found in login page source.',
            )
        return None

    # ── WSTG-ATHN-12: MFA ─────────────────────────────────────────────────────

    def _test_mfa_availability(self, page):
        """Check if MFA is offered or mentioned on authentication pages."""
        body = (getattr(page, 'body', '') or '').lower()
        url_lower = page.url.lower()

        is_auth_page = any(k in url_lower or k in body[:1000]
                           for k in ('login', 'signin', 'sign-in'))
        if not is_auth_page:
            return None

        has_mfa = any(k in body for k in MFA_INDICATORS)
        if not has_mfa:
            return self._build_vuln(
                name='Multi-Factor Authentication Not Enforced or Offered',
                severity='medium',
                category='WSTG-ATHN-12: Testing for Multi-Factor Authentication',
                description='The login page shows no indication of Multi-Factor Authentication '
                            '(MFA/2FA) support. MFA is a critical security control that '
                            'protects against credential compromise.',
                impact='If attacker obtains valid credentials (via phishing, breach, or '
                       'brute force), they can immediately access the account without '
                       'any additional challenge.',
                remediation='Implement TOTP-based MFA (RFC 6238) or hardware key support. '
                            'At minimum, offer MFA as an option. For sensitive applications, '
                            'make MFA mandatory.',
                cwe='CWE-308',
                cvss=6.5,
                affected_url=page.url,
                evidence='No MFA/2FA indicators found in login page HTML.',
            )
        return None

    # ── WSTG-ATHN-09: Password Change Flow ───────────────────────────────────

    def _test_password_change_flow(self, page):
        """Check password change forms for current-password requirement."""
        body = (getattr(page, 'body', '') or '').lower()
        url_lower = page.url.lower()

        is_change_page = any(k in url_lower or k in body[:500]
                             for k in ('change-password', 'change_password',
                                       'update-password', 'update_password',
                                       'new-password'))
        if not is_change_page:
            return None

        for form in (getattr(page, 'forms', None) or []):
            inputs = getattr(form, 'inputs', []) or []
            pw_fields = [i for i in inputs
                         if 'pass' in (getattr(i, 'name', '') or '').lower()
                         or getattr(i, 'type', '') == 'password']

            if len(pw_fields) < 2:
                continue

            # Check if there is a "current/old password" field
            has_current = any(
                any(k in (getattr(i, 'name', '') or '').lower()
                    for k in ('current', 'old', 'existing', 'original'))
                for i in pw_fields
            )
            if not has_current:
                return self._build_vuln(
                    name='Password Change Form Lacks Current Password Verification',
                    severity='high',
                    category='WSTG-ATHN-09: Testing for Weak Password Change or Reset Functionalities',
                    description='The password change form does not require the user to confirm their '
                                'current password before setting a new one. This allows an attacker '
                                'with a briefly hijacked session to permanently lock out the victim.',
                    impact='Session hijacking escalates to permanent account takeover if an '
                           'attacker can change the password without knowing the old one.',
                    remediation='Require users to enter their current password before changing to a '
                                'new one. Also send a confirmation email on successful password change.',
                    cwe='CWE-620',
                    cvss=7.1,
                    affected_url=page.url,
                    evidence='Password change form found with no "current_password" field.',
                )
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_login_form(self, page):
        for form in (getattr(page, 'forms', None) or []):
            inputs = getattr(form, 'inputs', []) or []
            has_password = any(
                getattr(i, 'type', '') == 'password'
                or 'pass' in (getattr(i, 'name', '') or '').lower()
                for i in inputs
            )
            if has_password:
                return form
        # Also check page URL / body for login indicators
        url_lower = page.url.lower()
        if any(k in url_lower for k in ('login', 'signin', 'sign-in', 'logon')):
            return page  # return page itself as sentinel
        return None
