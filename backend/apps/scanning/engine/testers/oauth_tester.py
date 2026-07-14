"""
OAuth Tester — Detects OAuth 2.0 misconfiguration vulnerabilities.

Covers:
  - Open redirect in redirect_uri parameter
  - Missing or predictable state parameter
  - Scope escalation possibilities
  - Token leakage via Referer header
  - PKCE bypass (missing code_challenge)
  - Client credential exposure in page source
"""
import logging
import re
import urllib.parse

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── OAuth endpoint indicators ────────────────────────────────────────────────
OAUTH_ENDPOINT_PATTERNS = [
    r'/oauth/authorize',
    r'/oauth2/authorize',
    r'/auth/authorize',
    r'/authorize\?',
    r'/oauth/token',
    r'/oauth2/token',
    r'/auth/token',
    r'/connect/authorize',
    r'/openid-connect/auth',
    r'/\.well-known/openid-configuration',
    r'/\.well-known/oauth-authorization-server',
]

OAUTH_PARAM_NAMES = [
    'redirect_uri', 'redirect_url', 'callback', 'callback_url',
    'return_uri', 'return_url',
]

EVIL_REDIRECT = 'https://evil.example.com/callback'

# ── Redirect_uri bypass payloads ─────────────────────────────────────────────
REDIRECT_URI_BYPASSES = [
    EVIL_REDIRECT,
    'https://evil.example.com%40legitimate.com/callback',
    'https://legitimate.com@evil.example.com/callback',
    'https://legitimate.com.evil.example.com/callback',
    'https://evil.example.com/callback?legitimate.com',
    'https://evil.example.com#@legitimate.com',
    'https://legitimate.com%2f%2fevil.example.com/callback',
    '//evil.example.com/callback',
    'https://legitimate.com/.evil.example.com/callback',
]

# ── Patterns indicating OAuth in page body ───────────────────────────────────
OAUTH_BODY_INDICATORS = re.compile(
    r'(?:client_id|client_secret|authorization_code|access_token|refresh_token'
    r'|redirect_uri|response_type=code|grant_type|scope=)',
    re.IGNORECASE,
)

CLIENT_SECRET_PATTERN = re.compile(
    r'(?:client_secret|clientSecret|client\.secret)\s*[:=]\s*["\']([^"\']{8,})["\']',
    re.IGNORECASE,
)

STATE_PARAM_RE = re.compile(r'[?&]state=([^&]*)', re.IGNORECASE)


class OAuthTester(BaseTester):
    """Test for OAuth 2.0 misconfigurations."""

    TESTER_NAME = 'OAuth Misconfiguration'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        params = getattr(page, 'parameters', {}) or {}

        is_oauth = self._is_oauth_endpoint(url, body)
        if not is_oauth and depth == 'shallow':
            return vulns

        # 1. Check for client credential exposure in page source
        vuln = self._check_client_credential_exposure(url, body)
        if vuln:
            vulns.append(vuln)

        # 2. Check for missing/weak state parameter
        vuln = self._check_state_parameter(url, body, params)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 3. Check for open redirect in redirect_uri
        if is_oauth:
            vuln = self._check_redirect_uri_bypass(url, params)
            if vuln:
                vulns.append(vuln)

        # 4. Check for token leakage via referer
        vuln = self._check_token_in_referer(url, body)
        if vuln:
            vulns.append(vuln)

        # 5. Check for PKCE bypass
        if is_oauth:
            vuln = self._check_pkce_bypass(url, params)
            if vuln:
                vulns.append(vuln)

        if depth == 'deep':
            # 6. Check for scope escalation
            vuln = self._check_scope_escalation(url, params)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Detection helpers ────────────────────────────────────────────────────

    def _is_oauth_endpoint(self, url: str, body: str) -> bool:
        """Check if the URL or body indicates an OAuth endpoint."""
        for pattern in OAUTH_ENDPOINT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        if OAUTH_BODY_INDICATORS.search(body):
            return True
        return False

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_client_credential_exposure(self, url: str, body: str):
        """Check for client_secret leaked in page source."""
        match = CLIENT_SECRET_PATTERN.search(body)
        if match:
            return self._build_vuln(
                name='OAuth Client Secret Exposure',
                severity='critical',
                category='Authentication',
                description=(
                    'OAuth client_secret is exposed in the page source code. '
                    'This allows attackers to impersonate the application.'
                ),
                impact='Full OAuth flow compromise, token theft, account takeover',
                remediation=(
                    'Never embed client_secret in client-side code. '
                    'Use PKCE flow for public clients. '
                    'Move secret to server-side backend.'
                ),
                cwe='CWE-522',
                cvss=9.1,
                affected_url=url,
                evidence=f'client_secret found: {match.group(0)[:60]}...',
            )
        return None

    def _check_state_parameter(self, url: str, body: str, params: dict):
        """Check for missing or predictable state parameter."""
        # Check URL query string
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)

        has_response_type = 'response_type' in qs or 'response_type' in params
        has_client_id = 'client_id' in qs or 'client_id' in params

        if not (has_response_type or has_client_id):
            # Also check body for OAuth forms
            if not re.search(r'response_type|client_id', body, re.IGNORECASE):
                return None

        # Check for state in URL
        state_match = STATE_PARAM_RE.search(url)
        state_in_params = params.get('state', '')

        if not state_match and not state_in_params:
            # Check body for state in forms
            if not re.search(r'name=["\']state["\']', body, re.IGNORECASE):
                return self._build_vuln(
                    name='OAuth Missing State Parameter',
                    severity='high',
                    category='Authentication',
                    description=(
                        'OAuth authorization request lacks a state parameter, '
                        'making it vulnerable to CSRF attacks on the OAuth flow.'
                    ),
                    impact='Cross-site request forgery on OAuth, login CSRF, account linking attacks',
                    remediation=(
                        'Always include a cryptographically random state parameter '
                        'in authorization requests. Validate it on the callback.'
                    ),
                    cwe='CWE-352',
                    cvss=7.4,
                    affected_url=url,
                    evidence='No state parameter found in OAuth authorization request',
                )

        # Check for predictable state values
        state_value = ''
        if state_match:
            state_value = state_match.group(1)
        elif state_in_params:
            state_value = str(state_in_params)

        if state_value and len(state_value) < 10:
            return self._build_vuln(
                name='OAuth Weak State Parameter',
                severity='medium',
                category='Authentication',
                description=(
                    f'OAuth state parameter is too short ({len(state_value)} chars), '
                    'making it potentially predictable or brute-forceable.'
                ),
                impact='CSRF attacks on OAuth flow with predictable state',
                remediation=(
                    'Use at least 32 bytes of cryptographically random data for state. '
                    'Bind state to the user session.'
                ),
                cwe='CWE-330',
                cvss=5.4,
                affected_url=url,
                evidence=f'Short state parameter: state={state_value}',
            )

        return None

    def _check_redirect_uri_bypass(self, url: str, params: dict):
        """Test for open redirect in redirect_uri parameter."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)

        for param_name in OAUTH_PARAM_NAMES:
            original_uri = qs.get(param_name, [None])[0] or params.get(param_name)
            if not original_uri:
                continue

            # Try bypass payloads
            for payload in REDIRECT_URI_BYPASSES[:4]:
                try:
                    test_qs = dict(qs)
                    test_qs[param_name] = [payload]
                    test_query = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=test_query)
                    )
                    resp = self._make_request('GET', test_url)
                    if resp and resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get('Location', '')
                        if 'evil.example.com' in location:
                            return self._build_vuln(
                                name='OAuth Redirect URI Bypass',
                                severity='high',
                                category='Authentication',
                                description=(
                                    'The OAuth redirect_uri parameter accepts '
                                    'arbitrary external domains, enabling authorization '
                                    'code/token theft via open redirect.'
                                ),
                                impact='OAuth token theft, account takeover via redirect manipulation',
                                remediation=(
                                    'Strictly validate redirect_uri against a whitelist of '
                                    'pre-registered URIs. Use exact string matching.'
                                ),
                                cwe='CWE-601',
                                cvss=8.2,
                                affected_url=test_url,
                                evidence=f'Redirect to {location} via {param_name}={payload}',
                            )
                except Exception:
                    continue

        return None

    def _check_token_in_referer(self, url: str, body: str):
        """Check for access_token in URL fragment or query (referer leakage)."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        fragment_qs = urllib.parse.parse_qs(parsed.fragment)

        token_params = ['access_token', 'token', 'id_token']
        for param in token_params:
            if param in qs:
                return self._build_vuln(
                    name='OAuth Token Leakage via URL',
                    severity='high',
                    category='Authentication',
                    description=(
                        f'OAuth {param} is present in the URL query string. '
                        'This can leak via Referer header, browser history, and server logs.'
                    ),
                    impact='Token theft via Referer header, browser history, proxy logs',
                    remediation=(
                        'Use response_type=code instead of implicit flow. '
                        'Never pass tokens in query strings. '
                        'Set Referrer-Policy: no-referrer for OAuth pages.'
                    ),
                    cwe='CWE-598',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'{param} found in URL query: ...{param}=***',
                )
            if param in fragment_qs:
                return self._build_vuln(
                    name='OAuth Implicit Flow Token Exposure',
                    severity='medium',
                    category='Authentication',
                    description=(
                        f'OAuth {param} is present in the URL fragment (implicit flow). '
                        'While fragments are not sent in Referer, they can leak via JS errors.'
                    ),
                    impact='Token exposure via JavaScript, browser extensions, error logging',
                    remediation=(
                        'Migrate from implicit flow to authorization code + PKCE. '
                        'Implicit flow is deprecated in OAuth 2.1.'
                    ),
                    cwe='CWE-598',
                    cvss=5.3,
                    affected_url=url,
                    evidence=f'{param} found in URL fragment',
                )

        return None

    def _check_pkce_bypass(self, url: str, params: dict):
        """Check if PKCE (code_challenge) is missing from auth requests."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)

        has_response_code = (
            qs.get('response_type', [''])[0] == 'code'
            or params.get('response_type') == 'code'
        )

        if not has_response_code:
            return None

        has_pkce = (
            'code_challenge' in qs
            or 'code_challenge' in params
        )

        if not has_pkce:
            return self._build_vuln(
                name='OAuth PKCE Not Enforced',
                severity='medium',
                category='Authentication',
                description=(
                    'OAuth authorization code request does not include PKCE '
                    '(code_challenge). This makes the flow vulnerable to '
                    'authorization code interception attacks.'
                ),
                impact='Authorization code interception, especially on mobile/SPA clients',
                remediation=(
                    'Require PKCE for all OAuth clients. Use code_challenge_method=S256.'
                ),
                cwe='CWE-345',
                cvss=5.9,
                affected_url=url,
                evidence='No code_challenge parameter in authorization request',
            )

        return None

    def _check_scope_escalation(self, url: str, params: dict):
        """Check if scope parameter can be manipulated."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)

        original_scope = qs.get('scope', [''])[0] or params.get('scope', '')
        if not original_scope:
            return None

        # Test adding admin/elevated scopes
        elevated_scopes = ['admin', 'openid profile email', 'read write delete']
        for new_scope in elevated_scopes:
            try:
                test_qs = dict(qs)
                test_qs['scope'] = [f'{original_scope} {new_scope}']
                test_query = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=test_query)
                )
                resp = self._make_request('GET', test_url)
                if resp and resp.status_code in (200, 302):
                    # If server doesn't reject elevated scope, it might accept it
                    if resp.status_code == 200 or (
                        resp.status_code == 302
                        and 'error' not in resp.headers.get('Location', '')
                    ):
                        return self._build_vuln(
                            name='OAuth Scope Escalation',
                            severity='high',
                            category='Authorization',
                            description=(
                                'The OAuth server may accept scope escalation by '
                                'adding additional scopes to the authorization request.'
                            ),
                            impact='Privilege escalation through scope manipulation',
                            remediation=(
                                'Validate requested scopes against the client\'s '
                                'registered allowed scopes. Reject unknown scopes.'
                            ),
                            cwe='CWE-269',
                            cvss=7.5,
                            affected_url=test_url,
                            evidence=f'Scope modified from "{original_scope}" to '
                                     f'"{original_scope} {new_scope}" without rejection',
                        )
            except Exception:
                continue

        return None
