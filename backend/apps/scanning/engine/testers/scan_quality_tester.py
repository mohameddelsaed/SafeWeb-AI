"""
Scan Quality & Coverage Auditor — Phase 48.

Meta-tester that validates foundational security controls by auditing:
  * Security header completeness (CSP, HSTS, X-Frame-Options, XCT-Options, etc.)
  * Cookie security attributes (HttpOnly, Secure, SameSite)
  * Server information leakage (Server, X-Powered-By, X-AspNet-Version)
  * Dangerous HTTP methods enabled (PUT, DELETE, TRACE, CONNECT)
  * Content Security Policy quality (unsafe-inline / unsafe-eval presence)

This tester acts as a QA gate — it ensures header-level and transport-level
security controls that are often missed by individual vulnerability testers are
systematically audited in every scan.

TESTER_NAME: 'Scan Quality & Coverage Auditor'
"""
from __future__ import annotations

import logging

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Required Security Headers ─────────────────────────────────────────────────
# (header_name, vuln_name, cwe, cvss, description, remediation)
REQUIRED_SECURITY_HEADERS: list[tuple] = [
    (
        'Content-Security-Policy',
        'Missing Content-Security-Policy Header',
        'CWE-693',
        5.3,
        (
            'A Content-Security-Policy (CSP) header was not found in the HTTP response. '
            'CSP is the primary defence-in-depth mechanism against Cross-Site Scripting '
            '(XSS) and data injection attacks by whitelisting trusted content sources.'
        ),
        (
            'Deploy a strict Content-Security-Policy header.  Start with a '
            'report-only policy and tighten progressively.  Avoid unsafe-inline '
            'and unsafe-eval directives.'
        ),
    ),
    (
        'Strict-Transport-Security',
        'Missing HTTP Strict Transport Security (HSTS)',
        'CWE-319',
        5.3,
        (
            'The Strict-Transport-Security (HSTS) header is absent.  Without HSTS, '
            'browsers may connect over plain HTTP, exposing users to SSL-stripping '
            'attacks and man-in-the-middle interception of credentials and session tokens.'
        ),
        (
            'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; '
            'preload" to all HTTPS responses.  Ensure the site is fully HTTPS-capable '
            'before enabling preload.'
        ),
    ),
    (
        'X-Content-Type-Options',
        'Missing X-Content-Type-Options Header',
        'CWE-16',
        4.3,
        (
            'The X-Content-Type-Options header is absent.  Without this header, '
            'browsers may MIME-sniff responses and interpret them as a different content '
            'type, enabling content-injection and drive-by-download attacks.'
        ),
        'Set "X-Content-Type-Options: nosniff" on all responses.',
    ),
    (
        'X-Frame-Options',
        'Missing X-Frame-Options Header',
        'CWE-693',
        4.3,
        (
            'The X-Frame-Options (XFO) header is absent.  Without it, attackers may '
            'embed the page in a hidden iframe and conduct clickjacking attacks that '
            'trick users into performing unintended actions.'
        ),
        (
            'Set "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN".  '
            'For modern browsers, use CSP frame-ancestors instead as a complementary control.'
        ),
    ),
    (
        'Referrer-Policy',
        'Missing Referrer-Policy Header',
        'CWE-200',
        3.7,
        (
            'The Referrer-Policy header is not present.  Without it, browsers may '
            'leak sensitive URL information (tokens, session IDs) in the Referer header '
            'to third-party sites and analytics endpoints.'
        ),
        (
            'Set "Referrer-Policy: strict-origin-when-cross-origin" or '
            '"Referrer-Policy: no-referrer" on all responses.'
        ),
    ),
    (
        'Permissions-Policy',
        'Missing Permissions-Policy Header',
        'CWE-16',
        3.1,
        (
            'The Permissions-Policy header (formerly Feature-Policy) is absent. '
            'Without it, the page grants browser feature access (camera, microphone, '
            'geolocation, payment, etc.) by default, broadening the attack surface.'
        ),
        (
            'Deploy a restrictive Permissions-Policy that disables features not '
            'required by the application, e.g. '
            '"Permissions-Policy: camera=(), microphone=(), geolocation=()".'
        ),
    ),
]

# ── Information-Disclosure Headers ────────────────────────────────────────────
# (header_name, vuln_name, cwe)
INFO_LEAKAGE_HEADERS: list[tuple[str, str, str]] = [
    ('Server', 'Server Header Information Disclosure', 'CWE-200'),
    ('X-Powered-By', 'X-Powered-By Header Information Disclosure', 'CWE-200'),
    ('X-AspNet-Version', 'ASP.NET Version Disclosure via X-AspNet-Version', 'CWE-200'),
    ('X-AspNetMvc-Version', 'ASP.NET MVC Version Disclosure', 'CWE-200'),
]

# ── Dangerous HTTP Methods ─────────────────────────────────────────────────────
DANGEROUS_METHODS: list[str] = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']

# ── Unsafe CSP Directives ─────────────────────────────────────────────────────
# (directive_string, vuln_name)
CSP_UNSAFE_DIRECTIVES: list[tuple[str, str]] = [
    ("'unsafe-inline'", "Content Security Policy Allows 'unsafe-inline'"),
    ("'unsafe-eval'", "Content Security Policy Allows 'unsafe-eval'"),
    ("'unsafe-hashes'", "Content Security Policy Allows 'unsafe-hashes'"),
]


class ScanQualityTester(BaseTester):
    """Meta-tester for scan quality & security coverage validation.

    Checks (by depth):
      shallow  → security header completeness from cached page headers only
      medium   → + live HTTP request: cookie security + server info leakage
      deep     → + dangerous HTTP method enumeration + CSP quality analysis

    All HTTP calls use ``_make_request`` (rate-limited, timeout-guarded).
    """

    TESTER_NAME = 'Scan Quality & Coverage Auditor'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        findings: list[dict] = []
        url = (
            getattr(page, 'url', None)
            or (page.get('url', '') if isinstance(page, dict) else '')
        )
        if not url:
            return findings

        # Extract headers from the crawled page (no HTTP yet)
        page_headers: dict = {}
        if hasattr(page, 'headers'):
            page_headers = page.headers or {}
        elif isinstance(page, dict):
            page_headers = page.get('headers', {}) or {}

        # ── Always: header completeness audit ────────────────────────────────
        findings.extend(self._audit_security_headers(url, page_headers))

        # ── Medium / Deep: live HTTP request ─────────────────────────────────
        resp = None
        if depth in ('medium', 'deep'):
            resp = self._make_request('GET', url)
            if resp is not None:
                findings.extend(self._audit_cookie_security(url, resp))
                findings.extend(
                    self._audit_server_info_leakage(url, dict(resp.headers))
                )

        # ── Deep: method enumeration + CSP quality ────────────────────────────
        if depth == 'deep':
            findings.extend(self._audit_dangerous_http_methods(url))
            csp = (
                page_headers.get('Content-Security-Policy')
                or page_headers.get('content-security-policy', '')
            )
            if not csp and resp is not None:
                csp = resp.headers.get('Content-Security-Policy', '')
            if csp:
                findings.extend(self._audit_csp_quality(url, csp))

        return findings

    # ── Sub-inspectors ────────────────────────────────────────────────────────

    def _audit_security_headers(self, url: str, headers: dict) -> list:
        """Report every mandatory security response header that is absent."""
        findings: list[dict] = []
        header_names_lower = {k.lower() for k in headers.keys()}

        for header_name, vuln_name, cwe, cvss, description, remediation in REQUIRED_SECURITY_HEADERS:
            if header_name.lower() not in header_names_lower:
                findings.append(self._build_vuln(
                    name=vuln_name,
                    severity='medium',
                    category='Security Configuration',
                    description=description,
                    impact=(
                        f'Absence of the {header_name} header weakens browser-level '
                        'security controls and may expose users to client-side attacks '
                        'such as XSS, clickjacking, or information leakage.'
                    ),
                    remediation=remediation,
                    cwe=cwe,
                    cvss=cvss,
                    affected_url=url,
                    evidence=f'HTTP response did not contain the {header_name} header.',
                ))
        return findings

    def _audit_cookie_security(self, url: str, resp) -> list:
        """Check Set-Cookie headers for missing HttpOnly, Secure, and SameSite flags."""
        findings: list[dict] = []
        set_cookie = resp.headers.get('Set-Cookie', '')
        if not set_cookie:
            return findings

        cookie_lower = set_cookie.lower()
        issues: list[tuple[str, str, str, str]] = []

        if 'httponly' not in cookie_lower:
            issues.append((
                'Cookie Missing HttpOnly Flag',
                'CWE-1004',
                (
                    'A Set-Cookie response header does not include the HttpOnly flag. '
                    'Without HttpOnly, client-side JavaScript can read the cookie via '
                    'document.cookie, enabling session hijacking after a successful XSS exploit.'
                ),
                'Set the HttpOnly flag on all session and authentication cookies.',
            ))

        if 'secure' not in cookie_lower:
            issues.append((
                'Cookie Missing Secure Flag',
                'CWE-614',
                (
                    'A Set-Cookie response header does not include the Secure flag. '
                    'Cookies without the Secure flag may be transmitted over unencrypted '
                    'HTTP connections, exposing them to network interception.'
                ),
                'Set the Secure flag on all cookies that carry sensitive information.',
            ))

        if 'samesite' not in cookie_lower:
            issues.append((
                'Cookie Missing SameSite Attribute',
                'CWE-352',
                (
                    'The Set-Cookie header does not include a SameSite attribute. '
                    'Without SameSite, the cookie is sent with cross-site requests, '
                    'enabling Cross-Site Request Forgery (CSRF) attacks.'
                ),
                'Set SameSite=Strict or SameSite=Lax on all non-cross-site cookies.',
            ))

        for vuln_name, cwe, description, remediation in issues:
            findings.append(self._build_vuln(
                name=vuln_name,
                severity='medium',
                category='Session Management',
                description=description,
                impact=(
                    'Insecure cookie attributes may allow session hijacking, CSRF attacks, '
                    'or exposure of session tokens over unencrypted channels.'
                ),
                remediation=remediation,
                cwe=cwe,
                cvss=4.3,
                affected_url=url,
                evidence=f'Set-Cookie: {set_cookie[:200]}',
            ))
        return findings

    def _audit_server_info_leakage(self, url: str, headers: dict) -> list:
        """Detect server technology disclosure through verbose response headers."""
        findings: list[dict] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, vuln_name, cwe in INFO_LEAKAGE_HEADERS:
            value = headers_lower.get(header_name.lower(), '')
            if value:
                findings.append(self._build_vuln(
                    name=vuln_name,
                    severity='low',
                    category='Information Disclosure',
                    description=(
                        f'The HTTP response contains the {header_name} header disclosing '
                        f'server technology information: "{value}". '
                        'This aids attacker reconnaissance and fingerprinting, '
                        'helping them select targeted exploits for the identified version.'
                    ),
                    impact=(
                        'Technology and version disclosure accelerates the attacker '
                        'reconnaissance phase and enables targeted exploit selection.'
                    ),
                    remediation=(
                        f'Remove or suppress the {header_name} header in the web server '
                        'or framework configuration. '
                        'Apache: ServerTokens Prod; Nginx: server_tokens off; '
                        'Node.js/Express: app.disable("x-powered-by").'
                    ),
                    cwe=cwe,
                    cvss=3.7,
                    affected_url=url,
                    evidence=f'{header_name}: {value}',
                ))
        return findings

    def _audit_dangerous_http_methods(self, url: str) -> list:
        """Issue an OPTIONS request and report any dangerous methods in Allow header."""
        findings: list[dict] = []
        try:
            resp = self._make_request('OPTIONS', url)
            if resp is None:
                return findings

            allow_header = (
                resp.headers.get('Allow', '')
                + ' '
                + resp.headers.get('Access-Control-Allow-Methods', '')
            )
            allow_upper = allow_header.upper()
            enabled_dangerous = [m for m in DANGEROUS_METHODS if m in allow_upper]

            if enabled_dangerous:
                findings.append(self._build_vuln(
                    name='Dangerous HTTP Methods Enabled',
                    severity='medium',
                    category='Security Configuration',
                    description=(
                        f'The server advertises support for potentially dangerous HTTP '
                        f'methods: {", ".join(enabled_dangerous)}. '
                        'TRACE enables Cross-Site Tracing (XST) attacks. '
                        'PUT/DELETE may allow unauthorised resource manipulation. '
                        'CONNECT can proxy arbitrary traffic through the server.'
                    ),
                    impact=(
                        'Dangerous HTTP methods may allow attackers to bypass security '
                        'controls, manipulate server-side resources, or leak credentials '
                        'via TRACE/XST.'
                    ),
                    remediation=(
                        'Disable all HTTP methods not required by the application. '
                        'Apache: <LimitExcept GET POST HEAD> Deny from all </LimitExcept>. '
                        'Nginx: limit_except GET POST { deny all; }. '
                        'Disable TRACE at the web server level.'
                    ),
                    cwe='CWE-16',
                    cvss=5.3,
                    affected_url=url,
                    evidence=f'OPTIONS Allow: {allow_header.strip()[:300]}',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_audit_dangerous_http_methods failed for %s: %s', url, exc)
        return findings

    def _audit_csp_quality(self, url: str, csp: str) -> list:
        """Analyse the Content-Security-Policy value for unsafe directives."""
        findings: list[dict] = []
        for directive, vuln_name in CSP_UNSAFE_DIRECTIVES:
            if directive in csp:
                findings.append(self._build_vuln(
                    name=vuln_name,
                    severity='medium',
                    category='Security Configuration',
                    description=(
                        f'The Content-Security-Policy header contains the {directive} directive. '
                        'This significantly weakens XSS protection by permitting inline '
                        'script/style execution or eval(), making the CSP largely ineffective '
                        'against XSS injection attacks.'
                    ),
                    impact=(
                        f'The {directive} directive allows attackers to inject and execute '
                        'scripts via XSS while remaining within the stated policy, '
                        'undermining the entire CSP defence.'
                    ),
                    remediation=(
                        f'Remove {directive} from the CSP. '
                        'Refactor all inline scripts to external files. '
                        'Use nonces (script-src nonce-...) or hashes for any genuinely '
                        'unavoidable inline scripts rather than blanket unsafe-inline.'
                    ),
                    cwe='CWE-693',
                    cvss=5.3,
                    affected_url=url,
                    evidence=f'Content-Security-Policy: {csp[:300]}',
                ))
        return findings
