"""
XS-Leak Tester — Detects cross-site leak attack vectors.

Covers:
  - Timing-based leaks (resource timing differences)
  - Error-based leaks (distinguishable error responses)
  - Navigation-based leaks (redirect differences by auth state)
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Endpoints likely to leak state ───────────────────────────────────────────
STATE_SENSITIVE_PATTERNS = [
    r'/api/', r'/user', r'/account', r'/profile',
    r'/search', r'/admin', r'/settings',
    r'/messages', r'/notifications', r'/inbox',
]

# ── Headers that enable XS-Leak mitigations ──────────────────────────────────
XS_LEAK_MITIGATIONS = {
    'Cross-Origin-Opener-Policy': ['same-origin', 'same-origin-allow-popups'],
    'Cross-Origin-Resource-Policy': ['same-origin', 'same-site'],
    'Cross-Origin-Embedder-Policy': ['require-corp'],
    'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
}

# ── Timing leak indicators ───────────────────────────────────────────────────
# Large content-length variations indicate timing side-channels
TIMING_SIZE_THRESHOLD = 5000  # bytes difference


class XSLeakTester(BaseTester):
    """Test for cross-site leak (XS-Leak) attack vectors."""

    TESTER_NAME = 'XS-Leak'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        headers = getattr(page, 'headers', {}) or {}

        # 1. Check missing XS-Leak mitigation headers
        vuln = self._check_missing_mitigations(url, headers)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Check error-based leak vectors
        vuln = self._check_error_based_leak(url, headers)
        if vuln:
            vulns.append(vuln)

        if depth == 'deep':
            # 3. Check navigation-based leaks (redirect differences)
            vuln = self._check_navigation_leak(url, body)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_missing_mitigations(self, url: str, headers: dict):
        """Check for missing cross-origin isolation headers."""
        missing = []
        for header, valid_values in XS_LEAK_MITIGATIONS.items():
            value = headers.get(header, '')
            if not any(v.lower() in value.lower() for v in valid_values):
                missing.append(header)

        # Only report if the page is state-sensitive
        is_sensitive = any(
            re.search(p, url, re.IGNORECASE) for p in STATE_SENSITIVE_PATTERNS
        )

        if missing and is_sensitive:
            return self._build_vuln(
                name='Missing XS-Leak Mitigations',
                severity='low',
                category='Security Misconfiguration',
                description=(
                    f'The page is missing cross-origin isolation headers: '
                    f'{", ".join(missing[:4])}. This enables cross-site leak '
                    'attacks that can infer user state from another origin.'
                ),
                impact='User state inference, login detection, content enumeration',
                remediation=(
                    'Set Cross-Origin-Opener-Policy: same-origin, '
                    'Cross-Origin-Resource-Policy: same-origin, and '
                    'Cross-Origin-Embedder-Policy: require-corp.'
                ),
                cwe='CWE-200',
                cvss=3.7,
                affected_url=url,
                evidence=f'Missing headers: {", ".join(missing[:4])}',
            )
        return None

    def _check_error_based_leak(self, url: str, headers: dict):
        """Check if error responses differ enough to leak information."""
        try:
            # Request an invalid variant to compare
            test_url = url.rstrip('/') + '/xs-leak-probe-nonexistent'
            resp = self._make_request('GET', test_url)
            if not resp:
                return None

            dict(getattr(resp, 'headers', {}))
            resp_body = getattr(resp, 'text', '')

            # If error page includes detailed info (stack trace, db info)
            error_indicators = [
                'traceback', 'exception', 'stack trace',
                'debug', 'internal server error',
            ]
            has_detailed_error = any(
                ind in resp_body.lower() for ind in error_indicators
            )

            # Different status codes per endpoint enable state detection
            if resp.status_code in (403, 401) and has_detailed_error:
                return self._build_vuln(
                    name='Error-Based XS-Leak Vector',
                    severity='low',
                    category='Information Disclosure',
                    description=(
                        'Error responses contain detailed information that '
                        'can be used to distinguish between authenticated '
                        'and unauthenticated states from a cross-origin context.'
                    ),
                    impact='Cross-origin state detection, user enumeration',
                    remediation=(
                        'Return generic error pages. Avoid detailed error info '
                        'in production. Use CORP: same-origin.'
                    ),
                    cwe='CWE-209',
                    cvss=3.7,
                    affected_url=test_url,
                    evidence=f'Detailed error (status {resp.status_code}) with debug info',
                )
        except Exception:
            pass
        return None

    def _check_navigation_leak(self, url: str, body: str):
        """Check for navigation-based leak vectors (redirect differences)."""
        try:
            # Test with and without credentials header
            resp_normal = self._make_request('GET', url)
            resp_no_cookie = self._make_request(
                'GET', url,
                headers={'Cookie': ''},
            )

            if not resp_normal or not resp_no_cookie:
                return None

            # Different redirects indicate auth-state leak
            loc_normal = resp_normal.headers.get('Location', '')
            loc_no_cookie = resp_no_cookie.headers.get('Location', '')

            if (loc_normal != loc_no_cookie
                    and (resp_normal.status_code in (301, 302, 303, 307)
                         or resp_no_cookie.status_code in (301, 302, 303, 307))):
                return self._build_vuln(
                    name='Navigation-Based XS-Leak',
                    severity='medium',
                    category='Information Disclosure',
                    description=(
                        'The server returns different redirect targets based '
                        'on authentication state. An attacker can detect if '
                        'a user is logged in from a cross-origin page.'
                    ),
                    impact='Login state detection, user identification',
                    remediation=(
                        'Use consistent redirect behavior regardless of auth. '
                        'Set COOP: same-origin to prevent window reference leaks.'
                    ),
                    cwe='CWE-200',
                    cvss=4.3,
                    affected_url=url,
                    evidence=(
                        f'Redirect differs: "{loc_normal}" vs "{loc_no_cookie}"'
                    ),
                )

            # Different response sizes indicate content leak
            body_normal = getattr(resp_normal, 'text', '')
            body_no_cookie = getattr(resp_no_cookie, 'text', '')
            size_diff = abs(len(body_normal) - len(body_no_cookie))

            if size_diff > TIMING_SIZE_THRESHOLD:
                return self._build_vuln(
                    name='Navigation-Based XS-Leak',
                    severity='low',
                    category='Information Disclosure',
                    description=(
                        f'Response size differs by {size_diff} bytes based '
                        'on authentication state, enabling timing-based '
                        'cross-site leak attacks.'
                    ),
                    impact='Auth state detection via response size',
                    remediation='Pad responses to uniform size. Use CORP: same-origin.',
                    cwe='CWE-200',
                    cvss=3.7,
                    affected_url=url,
                    evidence=f'Size diff: {len(body_normal)} vs {len(body_no_cookie)} bytes',
                )
        except Exception:
            pass
        return None
