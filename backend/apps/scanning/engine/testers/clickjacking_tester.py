"""
ClickjackingTester — Clickjacking / UI Redressing detection.
OWASP A05:2021 — Security Misconfiguration.

Tests for: missing X-Frame-Options, missing CSP frame-ancestors,
conflicting frame headers, and frameable authentication pages.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)


class ClickjackingTester(BaseTester):
    """Test for clickjacking protection."""

    TESTER_NAME = 'Clickjacking'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        try:
            response = self._make_request('GET', page.url)
        except Exception:
            return vulnerabilities

        if not response:
            return vulnerabilities

        xfo = response.headers.get('X-Frame-Options', '').upper()
        csp = response.headers.get('Content-Security-Policy', '')

        has_xfo = bool(xfo)
        has_frame_ancestors = 'frame-ancestors' in csp.lower()
        is_sensitive = self._is_sensitive_page(page)

        # Extract frame-ancestors value
        fa_value = ''
        if has_frame_ancestors:
            match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
            if match:
                fa_value = match.group(1).strip()

        # 1. No protection at all
        if not has_xfo and not has_frame_ancestors:
            severity = 'high' if is_sensitive else 'medium'
            cvss = 6.5 if is_sensitive else 4.7

            vulnerabilities.append(self._build_vuln(
                name='Missing Clickjacking Protection',
                severity=severity,
                category='Clickjacking',
                description='The page has no X-Frame-Options header and no CSP frame-ancestors '
                           'directive. It can be embedded in an iframe on any website.'
                           f'{" This is a sensitive page (authentication/account)." if is_sensitive else ""}',
                impact='Attackers can overlay transparent iframes to trick users into clicking '
                      'hidden buttons, performing unintended actions like changing settings, '
                      'transferring funds, or granting permissions.',
                remediation='Add X-Frame-Options: DENY or SAMEORIGIN header. '
                           'Add Content-Security-Policy: frame-ancestors \'self\' directive. '
                           'Both headers provide defense-in-depth.',
                cwe='CWE-1021',
                cvss=cvss,
                affected_url=page.url,
                evidence='X-Frame-Options: Not set\n'
                        'Content-Security-Policy frame-ancestors: Not set',
            ))

        # 2. X-Frame-Options set but CSP frame-ancestors missing
        elif has_xfo and not has_frame_ancestors:
            vulnerabilities.append(self._build_vuln(
                name='Missing CSP frame-ancestors (X-Frame-Options Only)',
                severity='low',
                category='Clickjacking',
                description=f'The page uses X-Frame-Options: {xfo} but lacks the CSP '
                           f'frame-ancestors directive. CSP frame-ancestors supersedes XFO '
                           f'in modern browsers and provides more granular control.',
                impact='Some edge cases in older browsers may not respect X-Frame-Options. '
                      'CSP frame-ancestors is the modern replacement.',
                remediation='Add Content-Security-Policy: frame-ancestors \'self\' alongside '
                           'X-Frame-Options for defense-in-depth.',
                cwe='CWE-1021',
                cvss=2.0,
                affected_url=page.url,
                evidence=f'X-Frame-Options: {xfo}\n'
                        f'Content-Security-Policy frame-ancestors: Not set',
            ))

        # 3. Check for weak XFO value
        if has_xfo and xfo not in ('DENY', 'SAMEORIGIN'):
            # Invalid or ALLOW-FROM (deprecated)
            if 'ALLOW-FROM' in xfo:
                vulnerabilities.append(self._build_vuln(
                    name='Deprecated X-Frame-Options ALLOW-FROM',
                    severity='medium',
                    category='Clickjacking',
                    description=f'X-Frame-Options: {xfo} uses the deprecated ALLOW-FROM directive. '
                               f'Modern browsers (Chrome, Firefox, Edge) ignore ALLOW-FROM entirely.',
                    impact='The page may be frameable in modern browsers since ALLOW-FROM is ignored.',
                    remediation='Replace ALLOW-FROM with CSP frame-ancestors directive: '
                               'Content-Security-Policy: frame-ancestors https://trusted-domain.com',
                    cwe='CWE-1021',
                    cvss=4.7,
                    affected_url=page.url,
                    evidence=f'X-Frame-Options: {xfo}',
                ))
            elif xfo and xfo not in ('DENY', 'SAMEORIGIN'):
                vulnerabilities.append(self._build_vuln(
                    name='Invalid X-Frame-Options Value',
                    severity='medium',
                    category='Clickjacking',
                    description=f'X-Frame-Options has an invalid value: "{xfo}". '
                               f'Valid values are DENY and SAMEORIGIN.',
                    impact='Browsers may ignore the invalid header, leaving the page unprotected.',
                    remediation='Set X-Frame-Options to DENY or SAMEORIGIN.',
                    cwe='CWE-1021',
                    cvss=4.7,
                    affected_url=page.url,
                    evidence=f'X-Frame-Options: {xfo}',
                ))

        # 4. Check for overly permissive frame-ancestors
        if has_frame_ancestors:
            if '*' in fa_value:
                vulnerabilities.append(self._build_vuln(
                    name='CSP frame-ancestors Wildcard',
                    severity='high',
                    category='Clickjacking',
                    description='The CSP frame-ancestors directive contains a wildcard (*), '
                               'allowing any site to embed this page.',
                    impact='The page can be framed by any website, enabling clickjacking attacks.',
                    remediation='Replace the wildcard with specific trusted origins or use \'self\'.',
                    cwe='CWE-1021',
                    cvss=6.5,
                    affected_url=page.url,
                    evidence=f'frame-ancestors: {fa_value}',
                ))

        # 5. Check for frameable sensitive pages (deep)
        if depth == 'deep' and not vulnerabilities:
            vuln = self._test_frame_embed(page)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_sensitive_page(self, page) -> bool:
        """Check if the page contains sensitive functionality."""
        url_lower = page.url.lower()
        body_lower = (page.body or '').lower()

        sensitive_url_patterns = [
            'login', 'signin', 'auth', 'account', 'profile',
            'settings', 'admin', 'transfer', 'payment', 'checkout',
            'password', 'delete', 'remove', 'confirm',
        ]

        sensitive_body_patterns = [
            'type="password"', 'input type="password"',
            'change password', 'delete account', 'confirm action',
            'transfer funds', 'payment method',
        ]

        has_sensitive_url = any(p in url_lower for p in sensitive_url_patterns)
        has_sensitive_body = any(p in body_lower for p in sensitive_body_patterns)

        return has_sensitive_url or has_sensitive_body

    def _test_frame_embed(self, page) -> object:
        """Test if the page can actually be framed."""
        # Check if JavaScript-based frame busting is present
        body = page.body or ''

        frame_busters = [
            'top.location', 'parent.location', 'self.location',
            'window.top', 'frameElement', 'top !== self',
            'top != self', 'top.location != self.location',
        ]

        has_frame_buster = any(fb in body for fb in frame_busters)

        if has_frame_buster:
            return self._build_vuln(
                name='JavaScript-Only Frame Busting',
                severity='info',
                category='Clickjacking',
                description='The page uses JavaScript-based frame busting but lacks proper '
                           'HTTP-level protection (X-Frame-Options / CSP frame-ancestors). '
                           'JavaScript frame busters can be bypassed.',
                impact='Attackers can use sandbox attribute or double-framing to bypass '
                      'JavaScript frame busters.',
                remediation='Always use HTTP headers (X-Frame-Options and CSP frame-ancestors) '
                           'as the primary defense. JavaScript frame busters are supplementary only.',
                cwe='CWE-1021',
                cvss=3.1,
                affected_url=page.url,
                evidence='JavaScript frame busting detected but no HTTP header protection.',
            )

        return None
