"""
AuthTester — Professional-grade authentication and session management testing.
OWASP A07:2021 — Identification and Authentication Failures.

Tests for: default credentials (100+ pairs), brute force protection,
account enumeration, session fixation, insecure cookies, password policy,
and HTTP-based login detection.
"""
import re
import logging
from .base_tester import BaseTester
from apps.scanning.engine.payloads.default_credentials import get_all_credentials

logger = logging.getLogger(__name__)


class AuthTester(BaseTester):
    """Test for authentication and session management weaknesses."""

    TESTER_NAME = 'Authentication'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Check for login forms
        login_form = self._find_login_form(page)
        if login_form:
            # Test default credentials
            if depth in ('medium', 'deep'):
                max_creds = 10 if depth == 'medium' else 30
                vuln = self._test_default_creds(login_form, page.url, max_creds)
                if vuln:
                    vulnerabilities.append(vuln)

            # Check for brute force protection
            vuln = self._test_brute_force_protection(login_form, page.url)
            if vuln:
                vulnerabilities.append(vuln)

            # Check for account enumeration
            vuln = self._test_account_enumeration(login_form, page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # Check for login over HTTP
        if page.url.startswith('http://'):
            vuln = self._check_http_login(page)
            if vuln:
                vulnerabilities.append(vuln)

        # Check password autocomplete
        vuln = self._check_password_autocomplete(page)
        if vuln:
            vulnerabilities.append(vuln)

        # Session cookie analysis (medium/deep)
        if depth in ('medium', 'deep'):
            vulns = self._check_session_cookies(page)
            vulnerabilities.extend(vulns)

        # Session fixation check (deep)
        if depth == 'deep' and login_form:
            vuln = self._test_session_fixation(login_form, page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # Cross-role session test: verify session isolation (medium/deep)
        if depth in ('medium', 'deep') and self.has_victim_session:
            vuln = self._test_cross_role_session(page)
            if vuln:
                vulnerabilities.append(vuln)

        # Password policy check (medium/deep)
        if depth in ('medium', 'deep'):
            for form in page.forms:
                vuln = self._check_password_policy(form, page.url)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

        return vulnerabilities

    def _find_login_form(self, page):
        """Identify a login form on the page."""
        for form in page.forms:
            has_password = False
            has_username = False
            for inp in form.inputs:
                if inp.input_type == 'password':
                    has_password = True
                if inp.input_type in ('text', 'email') or (
                    inp.name and any(k in inp.name.lower() for k in ('user', 'email', 'login', 'name'))
                ):
                    has_username = True
            if has_password and has_username:
                return form
        return None

    def _get_form_fields(self, form):
        """Extract username and password field names from form."""
        username_field = None
        password_field = None
        for inp in form.inputs:
            if inp.input_type == 'password':
                password_field = inp.name
            elif inp.input_type in ('text', 'email') or (
                inp.name and any(k in inp.name.lower() for k in ('user', 'email', 'login'))
            ):
                username_field = inp.name
        return username_field, password_field

    def _test_default_creds(self, form, page_url, max_creds=10):
        """Test for default/common credentials using 100+ credential pairs."""
        username_field, password_field = self._get_form_fields(form)
        if not username_field or not password_field:
            return None

        target_url = form.action or page_url
        all_creds = get_all_credentials()

        for username, password in all_creds[:max_creds]:
            data = {username_field: username, password_field: password}
            for inp in form.inputs:
                if inp.name not in data:
                    data[inp.name] = inp.value or ''

            response = self._make_request('POST', target_url, data=data, allow_redirects=False)
            if response and self._is_login_success(response):
                return self._build_vuln(
                    name='Default Credentials Accepted',
                    severity='critical',
                    category='Authentication',
                    description=f'The application accepts default credentials ({username}:{password}).',
                    impact='An attacker can gain full access to the application using widely known credentials.',
                    remediation='Remove default credentials. Force password change on first login. '
                               'Implement password complexity requirements.',
                    cwe='CWE-798',
                    cvss=9.8,
                    affected_url=target_url,
                    evidence=f'Login form accepted credentials: {username}:{"*" * len(password)}',
                )
        return None

    def _test_brute_force_protection(self, form, page_url):
        """Test if the application has brute force protection."""
        username_field, password_field = self._get_form_fields(form)
        if not username_field or not password_field:
            return None

        target_url = form.action or page_url
        blocked = False

        # Try 6 rapid invalid logins
        for i in range(6):
            data = {username_field: 'testuser', password_field: f'wrongpass{i}'}
            for inp in form.inputs:
                if inp.name not in data:
                    data[inp.name] = inp.value or ''

            response = self._make_request('POST', target_url, data=data)
            if response and response.status_code in (429, 403):
                blocked = True
                break
            if response and any(k in response.text.lower() for k in
                               ('captcha', 'locked', 'too many', 'rate limit', 'try again later')):
                blocked = True
                break

        if not blocked:
            return self._build_vuln(
                name='No Brute Force Protection',
                severity='medium',
                category='Authentication',
                description='The login form does not implement rate limiting or account lockout '
                           'after multiple failed attempts.',
                impact='Attackers can perform brute force attacks to guess user credentials.',
                remediation='Implement account lockout after 5-10 failed attempts. '
                           'Add rate limiting. Use CAPTCHA after failed attempts. '
                           'Consider progressive delays.',
                cwe='CWE-307',
                cvss=5.3,
                affected_url=target_url,
                evidence='6 rapid failed login attempts were accepted without rate limiting or lockout.',
            )
        return None

    def _test_account_enumeration(self, form, page_url):
        """Test if the application reveals whether a username exists."""
        username_field, password_field = self._get_form_fields(form)
        if not username_field or not password_field:
            return None

        target_url = form.action or page_url

        # Try a valid-looking username
        data1 = {username_field: 'admin', password_field: 'wrongpassword123!'}
        for inp in form.inputs:
            if inp.name not in data1:
                data1[inp.name] = inp.value or ''

        # Try a random non-existent username
        data2 = {username_field: 'nonexistentuser9827364', password_field: 'wrongpassword123!'}
        for inp in form.inputs:
            if inp.name not in data2:
                data2[inp.name] = inp.value or ''

        resp1 = self._make_request('POST', target_url, data=data1)
        resp2 = self._make_request('POST', target_url, data=data2)

        if resp1 and resp2:
            body1 = resp1.text.lower()
            body2 = resp2.text.lower()

            enum_hints = [
                'user not found', 'invalid username', 'no account',
                'username does not exist', 'account not found',
                'incorrect password', 'wrong password',
                'email not registered', 'user does not exist',
            ]

            for hint in enum_hints:
                in1 = hint in body1
                in2 = hint in body2
                if in1 != in2:
                    return self._build_vuln(
                        name='Account Enumeration via Login',
                        severity='low',
                        category='Authentication',
                        description='The login form reveals whether a username/email exists through different error messages.',
                        impact='Attackers can determine valid usernames for use in targeted attacks.',
                        remediation='Use generic error messages like "Invalid credentials" for all failed login attempts.',
                        cwe='CWE-204',
                        cvss=3.7,
                        affected_url=target_url,
                        evidence='Different error responses for existing vs non-existing usernames.',
                    )

            # Check for timing-based enumeration
            if abs(len(body1) - len(body2)) > 50:
                return self._build_vuln(
                    name='Potential Account Enumeration (Response Length)',
                    severity='low',
                    category='Authentication',
                    description='Login responses differ significantly in size between existing and non-existing usernames.',
                    impact='Response length differences can be used to enumerate valid accounts.',
                    remediation='Ensure identical responses for valid and invalid usernames.',
                    cwe='CWE-204',
                    cvss=3.7,
                    affected_url=target_url,
                    evidence=f'Response length diff: {abs(len(body1) - len(body2))} chars.',
                )
        return None

    def _check_http_login(self, page):
        """Check if login credentials are sent over HTTP."""
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type == 'password':
                    return self._build_vuln(
                        name='Login Form Over Unencrypted HTTP',
                        severity='high',
                        category='Authentication',
                        description='Login credentials are transmitted over unencrypted HTTP.',
                        impact='Credentials can be intercepted by network attackers (man-in-the-middle).',
                        remediation='Serve all login pages and form submissions over HTTPS.',
                        cwe='CWE-319',
                        cvss=7.5,
                        affected_url=page.url,
                        evidence=f'Login form found on HTTP page: {page.url}',
                    )
        return None

    def _check_password_autocomplete(self, page):
        """Check if password fields allow autocomplete."""
        body = page.body or ''
        # Check for password inputs without autocomplete="off"
        password_pattern = re.findall(
            r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>', body, re.IGNORECASE
        )
        for pw_input in password_pattern:
            if 'autocomplete' not in pw_input.lower() or 'autocomplete="off"' not in pw_input.lower():
                return self._build_vuln(
                    name='Password Autocomplete Enabled',
                    severity='info',
                    category='Authentication',
                    description='Password fields do not have autocomplete="off" attribute set.',
                    impact='Browsers may cache passwords, which could be exposed on shared or compromised devices.',
                    remediation='Add autocomplete="off" or autocomplete="new-password" to password fields.',
                    cwe='CWE-522',
                    cvss=2.0,
                    affected_url=page.url,
                    evidence='Password input field without autocomplete="off".',
                )
        return None

    def _test_cross_role_session(self, page):
        """Verify session isolation between different roles.

        If attacker session tokens also grant access to victim-only
        resources, sessions are not properly isolated.
        """
        # Attacker requests the page
        attacker_resp = self._make_request('GET', page.url)
        # Victim requests the same page
        victim_resp = self._make_victim_request('GET', page.url)

        if not attacker_resp or not victim_resp:
            return None

        # Both succeed — check if attacker sees victim-specific content
        if attacker_resp.status_code == 200 and victim_resp.status_code == 200:
            a_body = attacker_resp.text or ''
            v_body = victim_resp.text or ''
            # If responses are nearly identical and contain user-specific data,
            # sessions may not be properly isolated
            if (len(a_body) > 200 and len(v_body) > 200 and
                    a_body == v_body and
                    any(k in a_body.lower() for k in
                        ('profile', 'account', 'dashboard', 'my-', 'settings'))):
                return self._build_vuln(
                    name='Session Isolation Failure',
                    severity='high',
                    category='Authentication',
                    description='Different user sessions return identical user-specific content, '
                               'indicating session isolation is broken or sessions share state.',
                    impact='Users may see other users\' data or perform actions as other users.',
                    remediation='Ensure session tokens are unique per user and that server-side '
                               'session state is properly scoped to each authenticated identity.',
                    cwe='CWE-488',
                    cvss=7.5,
                    affected_url=page.url,
                    evidence=f'Attacker and victim sessions returned identical content '
                            f'({len(a_body)} bytes) on a user-specific page.',
                )
        return None

    def _check_session_cookies(self, page):
        """Analyze session cookie security attributes."""
        vulns = []
        # We need to make a request to get cookies
        response = self._make_request('GET', page.url)
        if not response:
            return vulns

        for cookie_name, cookie_value in response.cookies.items():
            cookie_header = response.headers.get('Set-Cookie', '')

            # Check for session-like cookie names
            if not any(k in cookie_name.lower() for k in
                      ('session', 'sid', 'token', 'auth', 'jwt', 'csrf')):
                continue

            issues = []
            # Check Secure flag
            if 'secure' not in cookie_header.lower():
                issues.append('Missing Secure flag')
            # Check HttpOnly flag
            if 'httponly' not in cookie_header.lower():
                issues.append('Missing HttpOnly flag')
            # Check SameSite flag
            if 'samesite' not in cookie_header.lower():
                issues.append('Missing SameSite flag')

            if issues:
                vulns.append(self._build_vuln(
                    name=f'Insecure Session Cookie: {cookie_name}',
                    severity='medium' if 'HttpOnly' in str(issues) else 'low',
                    category='Authentication',
                    description=f'The session cookie "{cookie_name}" has security issues: {", ".join(issues)}.',
                    impact='Session cookies without proper flags are vulnerable to theft via XSS (no HttpOnly), '
                          'interception over HTTP (no Secure), or CSRF attacks (no SameSite).',
                    remediation='Set all session cookies with: Secure, HttpOnly, and SameSite=Strict (or Lax).',
                    cwe='CWE-614',
                    cvss=4.3,
                    affected_url=page.url,
                    evidence=f'Cookie: {cookie_name}\nIssues: {", ".join(issues)}',
                ))

        return vulns

    def _test_session_fixation(self, form, page_url):
        """Test for session fixation vulnerability."""
        # Get initial session
        resp1 = self._make_request('GET', page_url)
        if not resp1 or not resp1.cookies:
            return None

        initial_cookies = dict(resp1.cookies)

        # Attempt login
        username_field, password_field = self._get_form_fields(form)
        if not username_field or not password_field:
            return None

        target_url = form.action or page_url
        data = {username_field: 'admin', password_field: 'admin'}
        for inp in form.inputs:
            if inp.name not in data:
                data[inp.name] = inp.value or ''

        resp2 = self._make_request('POST', target_url, data=data, cookies=initial_cookies)
        if not resp2:
            return None

        # Check if session ID changed after login
        post_cookies = dict(resp2.cookies)

        for name in initial_cookies:
            if any(k in name.lower() for k in ('session', 'sid', 'token')):
                if name in post_cookies and initial_cookies[name] == post_cookies[name]:
                    return self._build_vuln(
                        name='Session Fixation Vulnerability',
                        severity='high',
                        category='Authentication',
                        description='The session identifier does not change after authentication, '
                                   'making the application vulnerable to session fixation attacks.',
                        impact='An attacker can set a known session ID before the victim logs in, '
                              'then hijack the authenticated session.',
                        remediation='Regenerate the session ID after every authentication event. '
                                   'Invalidate the old session on login.',
                        cwe='CWE-384',
                        cvss=7.5,
                        affected_url=page_url,
                        evidence=f'Session cookie "{name}" was not regenerated after login attempt.',
                    )
        return None

    def _check_password_policy(self, form, page_url):
        """Check if weak passwords are accepted in registration forms."""
        # Look for registration forms
        is_register = False
        for inp in form.inputs:
            if inp.name and any(k in inp.name.lower() for k in ('confirm', 'register', 'signup')):
                is_register = True
                break

        if not is_register:
            return None

        password_field = None
        for inp in form.inputs:
            if inp.input_type == 'password':
                password_field = inp.name
                break

        if not password_field:
            return None

        # Try a weak password
        weak_passwords = ['123456', 'password', 'a']
        target_url = form.action or page_url

        for weak_pw in weak_passwords:
            data = {}
            for inp in form.inputs:
                if inp.input_type == 'password':
                    data[inp.name] = weak_pw
                elif inp.name:
                    data[inp.name] = inp.value or 'testuser@example.com'

            response = self._make_request('POST', target_url, data=data)
            if response and response.status_code in (200, 201, 302):
                body = response.text.lower()
                if not any(k in body for k in ('weak', 'too short', 'too simple',
                                                'too common', 'requirements', 'strength')):
                    return self._build_vuln(
                        name='Weak Password Policy',
                        severity='medium',
                        category='Authentication',
                        description=f'The registration form accepted a weak password ("{weak_pw}").',
                        impact='Users can set easily guessable passwords, making accounts vulnerable to brute force.',
                        remediation='Enforce minimum password length (12+ chars), complexity requirements, '
                                   'and check against known breached password lists (e.g., HaveIBeenPwned).',
                        cwe='CWE-521',
                        cvss=5.3,
                        affected_url=target_url,
                        evidence=f'Weak password "{weak_pw}" was accepted without complaint.',
                    )
        return None

    def _is_login_success(self, response):
        """Heuristic to determine if login was successful."""
        if response.status_code in (301, 302, 303):
            location = response.headers.get('Location', '')
            if any(k in location.lower() for k in ('dashboard', 'home', 'welcome', 'profile', 'account')):
                return True
        if response.status_code == 200:
            body = response.text.lower()
            if any(k in body for k in ('welcome', 'dashboard', 'logout', 'sign out')):
                if 'invalid' not in body and 'error' not in body and 'failed' not in body:
                    return True
        return False
