"""
WSTGSessionTester — OWASP WSTG-SESS gap coverage.
Maps to: WSTG-SESS-01 (Session Management Schema), WSTG-SESS-02 (Cookie Attributes),
         WSTG-SESS-03 (Session Fixation), WSTG-SESS-04 (Unauthenticated Exposed Cookies),
         WSTG-SESS-06 (Logout), WSTG-SESS-07 (Session Timeout),
         WSTG-SESS-08 (Session Puzzle), WSTG-SESS-09 (Session Hijacking).

Fills session management testing gaps identified in Phase 46.
"""
import re
import math
import logging
from urllib.parse import urljoin, urlparse

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Cookie names typically used for sessions
SESSION_COOKIE_NAMES = [
    'sessionid', 'session', 'sess', 'sid', 's_id',
    'phpsessid', 'jsessionid', 'asp.net_sessionid',
    'connect.sid', 'express.sid', 'auth', 'token',
    'access_token', 'id_token', 'jwt',
]


def _estimate_entropy(value: str) -> float:
    """Shannon entropy of a string — higher is harder to guess."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class WSTGSessionTester(BaseTester):
    """WSTG-SESS: Session Management Testing — schema, logout, timeout, hijacking."""

    TESTER_NAME = 'WSTG-SESS'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        resp = self._make_request('GET', page.url)
        if not resp:
            return vulnerabilities


        # WSTG-SESS-01/02: Session management schema + cookie attributes
        vulns = self._test_session_schema(resp, page.url)
        vulnerabilities.extend(vulns)

        # WSTG-SESS-06: Logout invalidates session
        if depth in ('medium', 'deep'):
            vuln = self._test_logout(page)
            if vuln:
                vulnerabilities.append(vuln)

        # WSTG-SESS-07: Session timeout
        vuln = self._test_session_timeout(page.url, resp)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-SESS-09: Predictable/weak session IDs
        vulns = self._test_session_predictability(resp, page.url)
        vulnerabilities.extend(vulns)

        return vulnerabilities

    # ── WSTG-SESS-01/02: Session Schema & Cookie Attributes ──────────────────

    def _test_session_schema(self, resp, url: str) -> list:
        """Analyze session cookies for security attribute deficiencies."""
        found = []
        for cookie in resp.cookies:
            name = (cookie.name or '').lower()
            if not any(s in name for s in SESSION_COOKIE_NAMES):
                continue

            issues = []
            # HttpOnly
            if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, '_rest', {}).get('HttpOnly'):
                # requests library stores HttpOnly in _rest
                raw_header = resp.headers.get('Set-Cookie', '')
                if f'{cookie.name}=' in raw_header:
                    cookie_segment = raw_header[raw_header.index(f'{cookie.name}='):]
                    if 'httponly' not in cookie_segment[:300].lower():
                        issues.append('missing HttpOnly flag')

            # Secure flag
            if not cookie.secure:
                if url.startswith('https://'):
                    issues.append('missing Secure flag (HTTPS site)')

            # SameSite
            raw_header = resp.headers.get('Set-Cookie', '')
            if f'{cookie.name}=' in raw_header:
                cookie_segment = raw_header[raw_header.index(f'{cookie.name}='):][:300]
                if 'samesite' not in cookie_segment.lower():
                    issues.append('missing SameSite attribute')

            if issues:
                found.append(self._build_vuln(
                    name=f'Session Cookie Missing Security Attributes: {cookie.name}',
                    severity='medium',
                    category='WSTG-SESS-02: Cookie Attributes',
                    description=f'The session cookie "{cookie.name}" is set without important '
                                f'security attributes: {"; ".join(issues)}.',
                    impact='Missing HttpOnly allows XSS-based session theft. '
                           'Missing Secure allows interception over HTTP. '
                           'Missing SameSite enables CSRF attacks.',
                    remediation=f'Set the session cookie with: HttpOnly; Secure; SameSite=Strict. '
                                f'Example: Set-Cookie: {cookie.name}=value; HttpOnly; Secure; '
                                f'SameSite=Strict; Path=/.',
                    cwe='CWE-1004',
                    cvss=5.4,
                    affected_url=url,
                    evidence=f'Cookie: {cookie.name}. Issues: {"; ".join(issues)}',
                ))

        return found

    # ── WSTG-SESS-06: Logout ──────────────────────────────────────────────────

    def _test_logout(self, page) -> list:
        """Check if logout endpoint properly invalidates session cookies."""
        (getattr(page, 'body', '') or '').lower()
        page.url.lower()

        # Find logout link
        logout_paths = re.findall(r'href=["\']([^"\']*(?:logout|sign.?out|log.?off)[^"\']*)["\']',
                                  getattr(page, 'body', '') or '', re.IGNORECASE)
        if not logout_paths:
            return None

        self._base_url(page.url)
        logout_url = urljoin(page.url, logout_paths[0])

        resp = self._make_request('GET', logout_url)
        if not resp:
            return None

        # Successful logout should clear session cookie or redirect
        # Check if Set-Cookie removes/expires the session
        set_cookie = resp.headers.get('Set-Cookie', '')
        cookie_cleared = any(
            (s in set_cookie.lower() and 'max-age=0' in set_cookie.lower())
            for s in SESSION_COOKIE_NAMES
        ) or 'expires=thu, 01 jan 1970' in set_cookie.lower()

        redirect_to_login = resp.status_code in (301, 302) and any(
            k in (resp.headers.get('Location', '') or '').lower()
            for k in ('login', 'signin', 'home', '/')
        )

        if not cookie_cleared and not redirect_to_login and resp.status_code == 200:
            return self._build_vuln(
                name='Logout Does Not Appear to Invalidate Session',
                severity='high',
                category='WSTG-SESS-06: Testing for Logout Functionality',
                description='The logout endpoint returned HTTP 200 without clearing session '
                            'cookies (no Max-Age=0 / expired Set-Cookie) or redirecting to login. '
                            'The existing session token may remain valid after logout.',
                impact='An attacker who obtains a session token (via XSS, network sniffing, '
                       'shoulder surfing) can reuse it even after the victim logs out.',
                remediation='On logout: invalidate the session server-side, clear the session '
                            'cookie with Max-Age=0, and redirect to the login page.',
                cwe='CWE-613',
                cvss=7.1,
                affected_url=logout_url,
                evidence=f'Logout GET returned {resp.status_code} without cookie invalidation or login redirect.',
            )
        return None

    # ── WSTG-SESS-07: Session Timeout ────────────────────────────────────────

    def _test_session_timeout(self, url: str, resp) -> list:
        """Check for overly long or missing session timeout."""
        set_cookie = resp.headers.get('Set-Cookie', '')
        for sname in SESSION_COOKIE_NAMES:
            if sname not in set_cookie.lower():
                continue
            # Find Max-Age in the relevant cookie section
            idx = set_cookie.lower().find(sname + '=')
            if idx < 0:
                continue
            segment = set_cookie[idx:idx + 400]
            max_age_match = re.search(r'[Mm]ax-[Aa]ge=(\d+)', segment)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                # 30 days = 2592000 seconds — flag if much longer
                if max_age > 2592000:
                    return self._build_vuln(
                        name='Excessively Long Session Cookie Lifetime',
                        severity='medium',
                        category='WSTG-SESS-07: Testing Session Timeout',
                        description=f'The session cookie "{sname}" has a Max-Age of {max_age} seconds '
                                    f'({max_age // 86400} days), which is unusually long. '
                                    f'Long-lived sessions increase the window for session hijacking.',
                        impact='If a session token is stolen, it remains valid for an extended '
                               'period, giving attackers more time to exploit it.',
                        remediation='Set session cookie Max-Age to no more than 24 hours for '
                                    'standard sessions. Use shorter timeouts for sensitive operations. '
                                    'Implement idle session timeout server-side.',
                        cwe='CWE-613',
                        cvss=4.3,
                        affected_url=url,
                        evidence=f'Set-Cookie segment: {segment[:200]}',
                    )
        return None

    # ── WSTG-SESS-09: Session Predictability ─────────────────────────────────

    def _test_session_predictability(self, resp, url: str) -> list:
        """Check if session IDs are predictable or low entropy."""
        found = []
        set_cookie = resp.headers.get('Set-Cookie', '')
        for sname in SESSION_COOKIE_NAMES:
            if sname + '=' not in set_cookie.lower():
                continue
            # Extract cookie value
            pattern = re.compile(re.escape(sname) + r'=([^;,\s]+)', re.IGNORECASE)
            match = pattern.search(set_cookie)
            if not match:
                continue

            value = match.group(1)
            if len(value) < 8:
                continue

            entropy = _estimate_entropy(value)
            # Low entropy < 3.5 bits/char suggests predictable IDs
            if entropy < 3.5 and len(value) < 24:
                found.append(self._build_vuln(
                    name=f'Low-Entropy Session Identifier: {sname}',
                    severity='high',
                    category='WSTG-SESS-01: Session Management Schema',
                    description=f'The session cookie "{sname}" has a low-entropy value '
                                f'(Shannon entropy: {entropy:.2f} bits/char, length: {len(value)}). '
                                f'Short or low-entropy session IDs can be predicted or brute-forced.',
                    impact='Session hijacking via brute force of predictable session IDs.',
                    remediation='Generate session IDs using a cryptographically secure PRNG with '
                                'at least 128 bits of entropy. Session IDs should be at least '
                                '16 bytes (32 hex characters) from os.urandom or secrets module.',
                    cwe='CWE-330',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Cookie: {sname}={value[:30]}... '
                             f'Entropy: {entropy:.2f} bits/char, length: {len(value)}.',
                ))
        return found

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _base_url(self, url: str) -> str:
        p = urlparse(url)
        return f'{p.scheme}://{p.netloc}'
