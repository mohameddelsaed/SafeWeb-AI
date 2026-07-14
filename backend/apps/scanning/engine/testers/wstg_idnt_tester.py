"""
WSTGIdentityTester — OWASP WSTG-IDNT gap coverage.
Maps to: WSTG-IDNT-01 (Role Definitions), WSTG-IDNT-02 (Registration Process),
         WSTG-IDNT-03 (Account Provisioning), WSTG-IDNT-04 (Account Enumeration),
         WSTG-IDNT-05 (Weak/Default Usernames).

Fills identity management testing gaps identified in Phase 46.
"""
import re
import logging

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Common default/weak usernames (WSTG-IDNT-05)
WEAK_USERNAMES = [
    'admin', 'administrator', 'root', 'test', 'guest', 'demo',
    'user', 'support', 'helpdesk', 'info', 'webmaster', 'operator',
    'manager', 'system', 'staff', 'service', 'superuser', 'sa',
]

# Response time threshold (ms) that suggests account enumeration by timing
TIMING_THRESHOLD_MS = 200

# Registration form field identifiers
REGISTER_INDICATORS = ['register', 'signup', 'sign-up', 'create.account', 'new.user']
LOGIN_INDICATORS = ['login', 'signin', 'sign-in', 'logon', 'authenticate']
RESET_INDICATORS = ['forgot', 'reset', 'recover', 'password.reset']


class WSTGIdentityTester(BaseTester):
    """WSTG-IDNT: Identity Management Testing — enumeration, provisioning, weak usernames."""

    TESTER_NAME = 'WSTG-IDNT'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # WSTG-IDNT-04: Account enumeration via login/registration response differences
        vuln = self._test_account_enumeration_responses(page)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-IDNT-05: Weak/default username acceptance
        if depth in ('medium', 'deep'):
            vuln = self._test_weak_username_acceptance(page)
            if vuln:
                vulnerabilities.append(vuln)

        # WSTG-IDNT-02: Registration process analysis
        if depth in ('medium', 'deep'):
            vuln = self._test_registration_process(page)
            if vuln:
                vulnerabilities.append(vuln)

        # WSTG-IDNT-01: Role definition exposure in page/forms
        vuln = self._test_role_exposure(page)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    # ── WSTG-IDNT-04: Account Enumeration ────────────────────────────────────

    def _test_account_enumeration_responses(self, page) -> list:
        """
        Detect different error messages for valid vs. invalid usernames.
        Checks login, registration, and password-reset forms.
        """
        body = (getattr(page, 'body', '') or '').lower()
        url_lower = page.url.lower()

        # On a login/reset page, check if page body already reveals enumerable messages
        is_login = any(k in url_lower or k in body[:500] for k in LOGIN_INDICATORS)
        is_reset = any(k in url_lower or k in body[:500] for k in RESET_INDICATORS)

        if not (is_login or is_reset):
            return None

        # Static analysis: check if page source reveals distinct responses for
        # valid/invalid accounts (common in poorly-designed error messages)
        enumeration_phrases = [
            'user not found',
            'no account with that email',
            'email address not registered',
            'that email does not exist',
            'invalid username',
            'username does not exist',
            'account not found',
        ]
        for phrase in enumeration_phrases:
            if phrase in body:
                return self._build_vuln(
                    name='Account Enumeration via Distinct Error Messages',
                    severity='medium',
                    category='WSTG-IDNT-04: Testing for Account Enumeration',
                    description='The application reveals whether a username or email exists through '
                                'distinct error messages on login/password-reset pages. Phrases like '
                                f'"{phrase}" enable username enumeration.',
                    impact='Attackers can build a list of valid accounts for targeted '
                           'credential stuffing or brute-force attacks.',
                    remediation='Return generic error messages that do not indicate whether '
                                'the username or password is incorrect (e.g., "Invalid credentials"). '
                                'Apply the same response time for valid and invalid accounts.',
                    cwe='CWE-204',
                    cvss=5.3,
                    affected_url=page.url,
                    evidence=f'Enumeration phrase found in page: "{phrase}"',
                )

        # Also check forms: if form submit returns different messages for valid/invalid
        for form in (getattr(page, 'forms', None) or []):
            action = getattr(form, 'action', '') or page.url
            method = (getattr(form, 'method', 'post') or 'post').upper()
            inputs = getattr(form, 'inputs', []) or []

            username_field = next(
                (i for i in inputs if any(n in (getattr(i, 'name', '') or '').lower()
                                          for n in ('user', 'email', 'login', 'username'))),
                None,
            )
            if not username_field:
                continue

            field_name = getattr(username_field, 'name', 'username')

            # Send request with an obviously non-existent account
            fake_user = 'nonexistent_test_user_x9z7q@example-test-xyz.com'
            data = {field_name: fake_user}
            resp_invalid = self._make_request(method, action, data=data)

            # Send request with a common username
            real_user = 'admin@example.com'
            data2 = {field_name: real_user}
            resp_valid = self._make_request(method, action, data=data2)

            if not resp_invalid or not resp_valid:
                continue

            # Different response lengths can indicate account existence leakage
            len_diff = abs(len(resp_invalid.text or '') - len(resp_valid.text or ''))
            if len_diff > 50:
                return self._build_vuln(
                    name='Potential Account Enumeration via Response Length Difference',
                    severity='medium',
                    category='WSTG-IDNT-04: Testing for Account Enumeration',
                    description='The login/reset form returns different response lengths for '
                                'likely-valid vs. non-existent accounts, potentially enabling '
                                'account enumeration.',
                    impact='Attackers can use response length discrepancies to determine '
                           'which usernames or emails are registered.',
                    remediation='Return identical response sizes for valid and invalid account lookups. '
                                'Use generic error messages and normalize response timing.',
                    cwe='CWE-204',
                    cvss=4.3,
                    affected_url=action,
                    evidence=f'Response length for fake user: {len(resp_invalid.text or "")}. '
                             f'Response length for admin: {len(resp_valid.text or "")}. '
                             f'Difference: {len_diff} bytes.',
                )
        return None

    # ── WSTG-IDNT-05: Weak/Default Usernames ─────────────────────────────────

    def _test_weak_username_acceptance(self, page):
        """Check if registration form accepts weak/default usernames."""
        for form in (getattr(page, 'forms', None) or []):
            action = getattr(form, 'action', '') or page.url
            url_lower = (action or page.url).lower()

            if not any(k in url_lower for k in REGISTER_INDICATORS):
                continue

            inputs = getattr(form, 'inputs', []) or []
            username_field = next(
                (i for i in inputs if any(n in (getattr(i, 'name', '') or '').lower()
                                          for n in ('user', 'username', 'login'))),
                None,
            )
            if not username_field:
                continue

            field_name = getattr(username_field, 'name', 'username')
            method = (getattr(form, 'method', 'post') or 'post').upper()

            for weak_name in WEAK_USERNAMES[:5]:  # test first 5
                data = {field_name: weak_name}
                resp = self._make_request(method, action, data=data)
                if not resp:
                    continue

                # If no rejection/validation error is found, it may be accepted
                body = (resp.text or '').lower()
                rejection_indicators = ['already taken', 'reserved', 'not allowed',
                                        'invalid username', 'choose a different']
                if not any(r in body for r in rejection_indicators) and resp.status_code < 400:
                    return self._build_vuln(
                        name=f'Registration Accepts Weak/Default Username: "{weak_name}"',
                        severity='low',
                        category='WSTG-IDNT-05: Testing for Weak or Unenforced Username Policy',
                        description=f'The registration form does not reject the default username '
                                    f'"{weak_name}". Accounts with predictable usernames are easier '
                                    f'targets for brute force and credential stuffing.',
                        impact='Accounts with trivially guessable usernames (admin, root, test) '
                               'increase risk of unauthorized access.',
                        remediation='Block registration of commonly-guessed or reserved usernames. '
                                    'Implement a username denylist and enforce uniqueness.',
                        cwe='CWE-521',
                        cvss=3.1,
                        affected_url=action,
                        evidence=f'Username "{weak_name}" submitted; no rejection detected. '
                                 f'Response status: {resp.status_code}.',
                    )
        return None

    # ── WSTG-IDNT-02: Registration Process ───────────────────────────────────

    def _test_registration_process(self, page):
        """Check for registration process weaknesses: no email verification hint."""
        body = (getattr(page, 'body', '') or '').lower()
        url_lower = page.url.lower()

        if not any(k in url_lower or k in body[:1000] for k in REGISTER_INDICATORS):
            return None

        # Check if no email verification is implied (form submits without CAPTCHA or verification note)
        has_captcha = any(k in body for k in ('captcha', 'recaptcha', 'hcaptcha', 'turnstile'))
        has_verify_text = any(k in body for k in ('verify your email', 'email confirmation',
                                                   'check your inbox', 'activate your account'))

        if not has_captcha and not has_verify_text:
            return self._build_vuln(
                name='Registration Lacks Email Verification or CAPTCHA',
                severity='low',
                category='WSTG-IDNT-02: Testing Registration Process',
                description='The registration page shows no indication of email verification '
                            'or CAPTCHA, potentially allowing automated bulk account creation.',
                impact='Attackers can automate mass account registration for spam, '
                       'abuse of free-tier limits, or platform pollution.',
                remediation='Implement CAPTCHA (or equivalent bot detection) on registration forms. '
                            'Require email verification before activating new accounts.',
                cwe='CWE-307',
                cvss=3.7,
                affected_url=page.url,
                evidence='No CAPTCHA widget or email verification text found on registration page.',
            )
        return None

    # ── WSTG-IDNT-01: Role Definition Exposure ───────────────────────────────

    def _test_role_exposure(self, page):
        """Detect role/permission values exposed in page source (hidden fields or JS)."""
        body = getattr(page, 'body', '') or ''

        # Look for role assignment in hidden inputs or JS variables
        role_patterns = [
            r'<input[^>]+name=["\']role["\'][^>]*value=["\'](\w+)["\']',
            r'<input[^>]+value=["\'](\w+)["\'][^>]*name=["\']role["\']',
            r'["\']role["\']\s*:\s*["\'](\w+)["\']',
            r'userRole\s*=\s*["\'](\w+)["\']',
            r'currentRole\s*=\s*["\'](\w+)["\']',
        ]
        for pattern in role_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                role_value = match.group(1)
                return self._build_vuln(
                    name='Role/Permission Value Exposed in Page Source',
                    severity='medium',
                    category='WSTG-IDNT-01: Role Definitions',
                    description=f'A role identifier ("{role_value}") is embedded in the page source '
                                f'as a hidden input or JavaScript variable. Client-side role values '
                                f'can be manipulated to escalate privileges.',
                    impact='Privilege escalation by modifying the role field from "user" to "admin".',
                    remediation='Never embed role/permission decisions in client-side code or hidden fields. '
                                'Enforce all authorization checks server-side based on authenticated session.',
                    cwe='CWE-269',
                    cvss=6.5,
                    affected_url=page.url,
                    evidence=f'Pattern matched: {match.group(0)[:200]}',
                )
        return None
