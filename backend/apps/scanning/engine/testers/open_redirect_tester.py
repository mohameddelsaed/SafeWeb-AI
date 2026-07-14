"""
Open Redirect Tester — Detects open redirect vulnerabilities via
parameter-based, path-based, and header-based redirect vectors.

Covers:
  - Parameter-based redirects (url=, redirect=, next=, return=, etc.)
  - Path-based redirects (/redirect/http://evil.com)
  - Post-login redirect abuse (login?next=)
  - Header-based redirects (Host, X-Forwarded-Host)
  - Bypass techniques (//evil.com, \/evil.com, encoding, null bytes)
  - JavaScript URI redirects (javascript:alert(1))
"""
import logging
import urllib.parse

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Common redirect parameter names ─────────────────────────────────────────
REDIRECT_PARAMS = [
    'url', 'redirect', 'redirect_url', 'redirect_uri', 'redirectUrl',
    'next', 'return', 'return_url', 'returnUrl', 'return_to', 'returnTo',
    'goto', 'go', 'target', 'dest', 'destination', 'redir', 'rurl',
    'continue', 'forward', 'out', 'view', 'ref', 'site', 'to',
    'callback', 'callback_url', 'callbackUrl', 'login_url',
    'checkout_url', 'image_url', 'service', 'RelayState',
]

# ── Evil domains for redirect testing ────────────────────────────────────────
EVIL_DOMAIN = 'evil.example.com'

# ── Redirect payloads with bypass techniques ─────────────────────────────────
REDIRECT_PAYLOADS = [
    # Basic
    f'https://{EVIL_DOMAIN}/',
    f'http://{EVIL_DOMAIN}/',

    # Protocol-relative
    f'//{EVIL_DOMAIN}/',
    f'\\\\{EVIL_DOMAIN}/',

    # Backslash trick (IIS/nginx)
    f'\\/{EVIL_DOMAIN}/',
    f'/\\{EVIL_DOMAIN}/',

    # Null byte / whitespace bypass
    f'https://{EVIL_DOMAIN}/%00',
    f'https://{EVIL_DOMAIN}/%09',
    f' https://{EVIL_DOMAIN}/',
    f'\thttps://{EVIL_DOMAIN}/',

    # URL encoding tricks
    f'https://{EVIL_DOMAIN}/%2f%2f',
    f'%2f%2f{EVIL_DOMAIN}/',
    f'%5c%5c{EVIL_DOMAIN}/',

    # @ credential trick
    f'https://target.com@{EVIL_DOMAIN}/',
    f'https://target.com%40{EVIL_DOMAIN}/',

    # Dotless domain
    f'https://{EVIL_DOMAIN}',

    # Data URI
    'data:text/html,<script>alert(1)</script>',

    # JavaScript URI
    'javascript:alert(document.domain)',
    'javascript://comment%0aalert(1)',
    'JavaSCript:alert(1)',

    # Double encoding
    f'https%3A%2F%2F{EVIL_DOMAIN}%2F',
    f'%68%74%74%70%73%3a%2f%2f{EVIL_DOMAIN}%2f',

    # Subdomain matching bypass
    f'https://{EVIL_DOMAIN}.target.com/',
    f'https://target.com.{EVIL_DOMAIN}/',
]


class OpenRedirectTester(BaseTester):
    """Detects open redirect vulnerabilities across multiple vectors."""

    TESTER_NAME = 'Open Redirect'
    REQUEST_TIMEOUT = 10

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        """Test for open redirect vulnerabilities."""
        vulns = []
        target = getattr(page, 'url', '')

        # 1. Parameter-based redirect testing
        vulns.extend(self._test_parameter_redirects(target, depth))

        # 2. Path-based redirect testing
        vulns.extend(self._test_path_redirects(target, depth))

        # 3. Header-based redirect testing
        if depth in ('medium', 'deep'):
            vulns.extend(self._test_header_redirects(target))

        # 4. Post-login redirect testing
        vulns.extend(self._test_login_redirects(target, depth))

        # 5. JavaScript URI redirect
        if depth == 'deep':
            vulns.extend(self._test_javascript_redirects(target))

        return vulns

    def _test_parameter_redirects(self, target: str, depth: str) -> list:
        """Test common redirect parameters for open redirect."""
        vulns = []
        max_params = 5 if depth == 'shallow' else (15 if depth == 'medium' else len(REDIRECT_PARAMS))
        max_payloads = 3 if depth == 'shallow' else (8 if depth == 'medium' else len(REDIRECT_PAYLOADS))

        for param in REDIRECT_PARAMS[:max_params]:
            for payload in REDIRECT_PAYLOADS[:max_payloads]:
                separator = '&' if '?' in target else '?'
                test_url = f'{target}{separator}{param}={urllib.parse.quote(payload, safe="")}'

                resp = self._make_request('GET', test_url, allow_redirects=False)
                if not resp:
                    continue

                redirect_url = self._get_redirect_location(resp)
                if redirect_url and self._is_open_redirect(redirect_url, payload):
                    is_js = payload.lower().startswith('javascript')
                    severity = 'high' if is_js else 'medium'

                    vulns.append(self._build_vuln(
                        name='Open Redirect via URL Parameter',
                        severity=severity,
                        category='Redirect',
                        description=(
                            f'The parameter "{param}" at {target} accepts external URLs and '
                            f'redirects users without validation. The payload "{payload[:80]}" '
                            f'resulted in a redirect to an external domain.'
                        ),
                        impact=(
                            'Phishing attacks — users trust the original domain but are '
                            'redirected to a malicious site. Can be chained with OAuth flows '
                            'for token theft, or used to bypass URL-based security filters.'
                        ),
                        remediation=(
                            '1. Use an allowlist of permitted redirect destinations. '
                            '2. Validate that redirect URLs are relative paths or same-origin. '
                            '3. Display an interstitial warning page for external redirects. '
                            '4. Use indirect references (e.g., numeric IDs mapped to URLs).'
                        ),
                        cwe='CWE-601',
                        cvss=6.1,
                        affected_url=test_url[:500],
                        evidence=f'Parameter: {param}\nPayload: {payload}\nRedirected to: {redirect_url}',
                    ))
                    return vulns  # One confirmed finding is sufficient

        return vulns

    def _test_path_redirects(self, target: str, depth: str) -> list:
        """Test path-based redirect patterns."""
        vulns = []
        base = target.rstrip('/')
        redirect_paths = [
            f'/redirect/{EVIL_DOMAIN}',
            f'/redirect/https://{EVIL_DOMAIN}/',
            f'/go/{EVIL_DOMAIN}',
            f'/out/{EVIL_DOMAIN}',
            f'/link/{EVIL_DOMAIN}',
            f'/proxy/{EVIL_DOMAIN}',
        ]

        max_paths = 2 if depth == 'shallow' else len(redirect_paths)

        for path in redirect_paths[:max_paths]:
            url = base + path
            resp = self._make_request('GET', url, allow_redirects=False)
            if not resp:
                continue

            redirect_url = self._get_redirect_location(resp)
            if redirect_url and EVIL_DOMAIN in redirect_url:
                vulns.append(self._build_vuln(
                    name='Open Redirect via URL Path',
                    severity='medium',
                    category='Redirect',
                    description=(
                        f'The path-based redirect at {url} redirects to an external domain '
                        f'without validation.'
                    ),
                    impact='Phishing and token theft via path-based open redirect.',
                    remediation=(
                        '1. Validate destination URLs against an allowlist. '
                        '2. Remove or restrict path-based redirect functionality. '
                        '3. Require authentication for redirect endpoints.'
                    ),
                    cwe='CWE-601',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'Path redirect to: {redirect_url}',
                ))
                break

        return vulns

    def _test_header_redirects(self, target: str) -> list:
        """Test Host header injection causing redirects."""
        vulns = []
        evil_headers = [
            {'Host': EVIL_DOMAIN},
            {'X-Forwarded-Host': EVIL_DOMAIN},
            {'X-Forwarded-For': EVIL_DOMAIN},
            {'X-Original-URL': f'https://{EVIL_DOMAIN}/'},
        ]

        for headers in evil_headers:
            resp = self._make_request('GET', target, headers=headers, allow_redirects=False)
            if not resp:
                continue

            redirect_url = self._get_redirect_location(resp)
            body = resp.text or ''

            if redirect_url and EVIL_DOMAIN in redirect_url:
                header_name = list(headers.keys())[0]
                vulns.append(self._build_vuln(
                    name=f'Open Redirect via {header_name} Header',
                    severity='medium',
                    category='Redirect',
                    description=(
                        f'The {header_name} header injection at {target} causes a redirect '
                        f'to an attacker-controlled domain ({EVIL_DOMAIN}).'
                    ),
                    impact=(
                        'Cache poisoning, phishing, or password reset link hijacking '
                        'via Host header manipulation.'
                    ),
                    remediation=(
                        f'1. Ignore or validate the {header_name} header on the server. '
                        '2. Use a hardcoded base URL instead of trusting Host headers. '
                        '3. Configure the web server to reject unexpected Host values.'
                    ),
                    cwe='CWE-601',
                    cvss=6.1,
                    affected_url=target,
                    evidence=f'Header: {header_name}: {EVIL_DOMAIN}\nRedirected to: {redirect_url}',
                ))
                break

            # Check if evil domain appears in response body (e.g., in links)
            if EVIL_DOMAIN in body:
                header_name = list(headers.keys())[0]
                vulns.append(self._build_vuln(
                    name=f'Host Header Injection via {header_name}',
                    severity='low',
                    category='Redirect',
                    description=(
                        f'The {header_name} header value is reflected in the page body at {target}. '
                        f'While not a direct redirect, this can enable phishing via modified links.'
                    ),
                    impact='Link manipulation in emails (password reset poisoning).',
                    remediation=f'1. Do not use {header_name} header to generate URLs. ',
                    cwe='CWE-644',
                    cvss=4.3,
                    affected_url=target,
                    evidence=f'{header_name}: {EVIL_DOMAIN} reflected in body.',
                ))
                break

        return vulns

    def _test_login_redirects(self, target: str, depth: str) -> list:
        """Test post-login redirect parameters on auth endpoints."""
        vulns = []
        base = target.rstrip('/')
        login_paths = ['/login', '/signin', '/auth/login', '/accounts/login', '/api/auth/login']

        for path in login_paths:
            url = base + path
            # Test with redirect parameter
            for param in ['next', 'redirect', 'return_to', 'continue', 'returnUrl']:
                payload = f'https://{EVIL_DOMAIN}/'
                test_url = f'{url}?{param}={urllib.parse.quote(payload)}'

                resp = self._make_request('GET', test_url, allow_redirects=False)
                if not resp:
                    continue

                body = resp.text or ''
                redirect_url = self._get_redirect_location(resp)

                # Check if the evil domain appears in hidden form fields or redirects
                if (redirect_url and EVIL_DOMAIN in redirect_url) or \
                   (EVIL_DOMAIN in body and ('value=' in body or 'action=' in body)):
                    vulns.append(self._build_vuln(
                        name='Open Redirect via Post-Login Flow',
                        severity='high',
                        category='Redirect',
                        description=(
                            f'The login page at {url} accepts a "{param}" parameter with '
                            f'an external URL. After successful authentication, the user may '
                            f'be redirected to an attacker-controlled site with their session.'
                        ),
                        impact=(
                            'Post-authentication token theft — user logs in legitimately '
                            'but is redirected to a phishing site that captures their '
                            'session or credentials. High-value for OAuth token theft.'
                        ),
                        remediation=(
                            '1. Only allow relative redirect URLs after login. '
                            '2. Validate redirect destinations against a strict allowlist. '
                            '3. Strip external URLs from post-login redirect parameters. '
                            '4. Use CSRF tokens in redirect flows.'
                        ),
                        cwe='CWE-601',
                        cvss=7.4,
                        affected_url=test_url[:500],
                        evidence=f'Param: {param}\nEvil domain found in redirect or form.',
                    ))
                    return vulns

        return vulns

    def _test_javascript_redirects(self, target: str) -> list:
        """Test for javascript: URI scheme in redirect parameters."""
        vulns = []
        js_payloads = [
            'javascript:alert(document.domain)',
            'javascript://comment%0aalert(1)',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ]

        for param in REDIRECT_PARAMS[:10]:
            for payload in js_payloads:
                separator = '&' if '?' in target else '?'
                test_url = f'{target}{separator}{param}={urllib.parse.quote(payload, safe="")}'

                resp = self._make_request('GET', test_url)
                if not resp:
                    continue

                body = resp.text or ''

                # Check if JS URI is reflected in page (e.g., in href, src, or meta refresh)
                if payload in body or urllib.parse.unquote(payload) in body:
                    vulns.append(self._build_vuln(
                        name='JavaScript URI Open Redirect (XSS)',
                        severity='high',
                        category='Redirect',
                        description=(
                            f'The parameter "{param}" at {target} accepts javascript: or data: '
                            f'URIs that are reflected in the page, enabling XSS via redirect '
                            f'parameter injection.'
                        ),
                        impact=(
                            'Cross-site scripting via javascript: URI in redirect parameter. '
                            'Can lead to session hijacking and credential theft.'
                        ),
                        remediation=(
                            '1. Block javascript: and data: URI schemes in redirect parameters. '
                            '2. Only allow http: and https: schemes. '
                            '3. Validate redirect URLs are relative or same-origin.'
                        ),
                        cwe='CWE-79',
                        cvss=7.5,
                        affected_url=test_url[:500],
                        evidence=f'JS URI reflected in page via param "{param}".',
                    ))
                    return vulns

        return vulns

    def _get_redirect_location(self, resp) -> str:
        """Extract redirect location from response."""
        if resp.status_code in (301, 302, 303, 307, 308):
            return resp.headers.get('Location', '')

        # Check meta refresh
        body = resp.text or ''
        import re
        meta_match = re.search(
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\'>\s]+)',
            body, re.IGNORECASE
        )
        if meta_match:
            return meta_match.group(1)

        # Check window.location in script
        loc_match = re.search(
            r'(?:window\.location|document\.location|location\.href)\s*=\s*["\']([^"\']+)',
            body, re.IGNORECASE
        )
        if loc_match:
            return loc_match.group(1)

        return ''

    def _is_open_redirect(self, redirect_url: str, payload: str) -> bool:
        """Check if the redirect URL indicates an open redirect."""
        redirect_lower = redirect_url.lower()
        decoded = urllib.parse.unquote(redirect_lower)

        # Check for evil domain in redirect
        if EVIL_DOMAIN in decoded:
            return True

        # Check for javascript: or data: URI
        if decoded.strip().startswith(('javascript:', 'data:')):
            return True

        # Check for protocol-relative redirect to evil domain
        if decoded.startswith('//') and EVIL_DOMAIN in decoded:
            return True

        return False
