"""
Authentication Flow Testing Engine — Deep testing of auth mechanisms.

Tests:
  - Password reset token analysis (predictability, reuse, expiry)
  - OTP bypass (response manipulation, status code bypass)
  - Account enumeration (timing and response differences)
  - Registration abuse (duplicate email, email case bypass)
  - Forgot password host header manipulation
"""
import logging
import re
import json

logger = logging.getLogger(__name__)

# ── Password reset endpoints ─────────────────────────────────────────────────
RESET_ENDPOINTS = [
    '/api/auth/forgot-password',
    '/api/auth/reset-password',
    '/api/password/reset',
    '/api/forgot-password',
    '/api/reset',
    '/password/forgot',
    '/account/recover',
]

# ── OTP / 2FA endpoints ─────────────────────────────────────────────────────
OTP_ENDPOINTS = [
    '/api/auth/verify-otp',
    '/api/auth/2fa/verify',
    '/api/verify-code',
    '/api/otp/verify',
    '/api/mfa/verify',
    '/verify-otp',
]

# ── Login endpoints ──────────────────────────────────────────────────────────
LOGIN_ENDPOINTS = [
    '/api/auth/login',
    '/api/login',
    '/login',
    '/api/auth/signin',
    '/signin',
]

# ── Registration endpoints ───────────────────────────────────────────────────
REGISTER_ENDPOINTS = [
    '/api/auth/register',
    '/api/auth/signup',
    '/api/register',
    '/api/signup',
    '/register',
    '/signup',
]

# ── OTP bypass payloads ─────────────────────────────────────────────────────
OTP_BYPASS_PAYLOADS = [
    {'otp': '000000'},
    {'otp': '123456'},
    {'otp': ''},
    {'otp': '0'},
    {'code': '000000'},
    {'code': ''},
    {'token': ''},
    {'verification_code': '000000'},
]

# ── Host header manipulation payloads ────────────────────────────────────────
HOST_HEADER_PAYLOADS = [
    'evil.com',
    'attacker.com',
    'localhost',
    '127.0.0.1',
]


class AuthFlowTester:
    """
    Test authentication flows for logic vulnerabilities.

    Usage:
        tester = AuthFlowTester(make_request_fn)
        findings = tester.test(url, body, depth='medium')
    """

    def __init__(self, make_request_fn):
        self._request = make_request_fn

    def test(self, url: str, body: str = '', depth: str = 'medium') -> list:
        """
        Run authentication flow tests.

        Returns list of finding dicts with keys:
            technique, detail, severity, evidence.
        """
        findings = []
        base = url.rstrip('/')

        # 1. Account enumeration
        findings.extend(self._test_account_enumeration(base))

        if depth == 'shallow':
            return findings

        # 2. OTP bypass
        findings.extend(self._test_otp_bypass(base))

        # 3. Password reset token analysis
        findings.extend(self._test_reset_token_analysis(base))

        if depth == 'deep':
            # 4. Registration abuse
            findings.extend(self._test_registration_abuse(base))

            # 5. Host header manipulation on password reset
            findings.extend(self._test_host_header_reset(base))

        return findings

    # ── Account enumeration ──────────────────────────────────────────────

    def _test_account_enumeration(self, base_url: str) -> list:
        """Detect account enumeration via response differences."""
        findings = []
        existing_email = 'admin@example.com'
        nonexistent_email = 'xyznonexistent9281@example.com'

        for endpoint in LOGIN_ENDPOINTS:
            url = base_url + endpoint
            try:
                resp_exist = self._request(
                    'POST', url,
                    json={'email': existing_email, 'password': 'WrongPassword123!'},
                )
                resp_noexist = self._request(
                    'POST', url,
                    json={'email': nonexistent_email, 'password': 'WrongPassword123!'},
                )
                if not resp_exist or not resp_noexist:
                    continue

                text_exist = getattr(resp_exist, 'text', '')
                text_noexist = getattr(resp_noexist, 'text', '')
                status_exist = getattr(resp_exist, 'status_code', 0)
                status_noexist = getattr(resp_noexist, 'status_code', 0)

                # Different status codes = enumeration
                if status_exist != status_noexist:
                    findings.append({
                        'technique': 'account_enumeration',
                        'detail': f'Account enumeration via status code difference at {endpoint}',
                        'severity': 'medium',
                        'evidence': f'Existing: HTTP {status_exist}, Non-existing: HTTP {status_noexist}',
                    })
                    return findings

                # Different response lengths (significant diff)
                if abs(len(text_exist) - len(text_noexist)) > 20:
                    findings.append({
                        'technique': 'account_enumeration',
                        'detail': f'Account enumeration via response length at {endpoint}',
                        'severity': 'medium',
                        'evidence': f'Existing: {len(text_exist)} bytes, Non-existing: {len(text_noexist)} bytes',
                    })
                    return findings

                # Different error messages
                if text_exist != text_noexist:
                    findings.append({
                        'technique': 'account_enumeration',
                        'detail': f'Account enumeration via response diff at {endpoint}',
                        'severity': 'low',
                        'evidence': 'Different response bodies for existing vs non-existing accounts',
                    })
                    return findings

            except Exception:
                continue
        return findings

    # ── OTP bypass ───────────────────────────────────────────────────────

    def _test_otp_bypass(self, base_url: str) -> list:
        """Test OTP/2FA bypass techniques."""
        findings = []
        for endpoint in OTP_ENDPOINTS:
            url = base_url + endpoint
            for payload in OTP_BYPASS_PAYLOADS:
                try:
                    resp = self._request('POST', url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)
                    text = getattr(resp, 'text', '')

                    if status == 200 and self._looks_like_auth_success(text):
                        field = list(payload.keys())[0]
                        val = payload[field]
                        findings.append({
                            'technique': 'otp_bypass',
                            'detail': f'OTP bypass with {field}="{val}" at {endpoint}',
                            'severity': 'critical',
                            'evidence': f'POST {endpoint} with {json.dumps(payload)} → HTTP {status}',
                        })
                        return findings
                except Exception:
                    continue
        return findings

    # ── Password reset token analysis ────────────────────────────────────

    def _test_reset_token_analysis(self, base_url: str) -> list:
        """Analyse password reset tokens for weaknesses."""
        findings = []
        tokens = []

        for endpoint in RESET_ENDPOINTS:
            url = base_url + endpoint
            for _ in range(3):
                try:
                    resp = self._request(
                        'POST', url,
                        json={'email': 'test@example.com'},
                    )
                    if not resp:
                        continue
                    text = getattr(resp, 'text', '')
                    # Try to extract token from response
                    token = self._extract_token(text)
                    if token:
                        tokens.append(token)
                except Exception:
                    continue

            if len(tokens) >= 2:
                break

        if len(tokens) >= 2:
            # Check for predictability — sequential or similar tokens
            if self._tokens_are_sequential(tokens):
                findings.append({
                    'technique': 'reset_token_predictable',
                    'detail': 'Password reset tokens appear sequential/predictable',
                    'severity': 'critical',
                    'evidence': f'Tokens: {", ".join(tokens[:3])}',
                })

            # Check for short tokens
            avg_len = sum(len(t) for t in tokens) / len(tokens)
            if avg_len < 16:
                findings.append({
                    'technique': 'reset_token_weak',
                    'detail': f'Password reset tokens are short (avg {avg_len:.0f} chars)',
                    'severity': 'high',
                    'evidence': f'Token lengths: {", ".join(str(len(t)) for t in tokens)}',
                })

        return findings

    # ── Registration abuse ───────────────────────────────────────────────

    def _test_registration_abuse(self, base_url: str) -> list:
        """Test registration for email case bypass and duplication."""
        findings = []
        test_email = 'Test.User@Example.Com'
        test_email_lower = test_email.lower()

        for endpoint in REGISTER_ENDPOINTS:
            url = base_url + endpoint
            # Try registering with mixed case
            try:
                resp1 = self._request(
                    'POST', url,
                    json={'email': test_email, 'password': 'TestPass123!'},
                )
                resp2 = self._request(
                    'POST', url,
                    json={'email': test_email_lower, 'password': 'TestPass123!'},
                )
                if not resp1 or not resp2:
                    continue

                s1 = getattr(resp1, 'status_code', 0)
                s2 = getattr(resp2, 'status_code', 0)

                # If both succeed, email case bypass exists
                if s1 in (200, 201) and s2 in (200, 201):
                    findings.append({
                        'technique': 'registration_abuse',
                        'detail': f'Email case bypass — two accounts for same email at {endpoint}',
                        'severity': 'high',
                        'evidence': f'"{test_email}" and "{test_email_lower}" both registered: HTTP {s1}, {s2}',
                    })
                    return findings
            except Exception:
                continue
        return findings

    # ── Host header manipulation ─────────────────────────────────────────

    def _test_host_header_reset(self, base_url: str) -> list:
        """Test forgot-password with Host header manipulation."""
        findings = []
        for endpoint in RESET_ENDPOINTS:
            url = base_url + endpoint
            for evil_host in HOST_HEADER_PAYLOADS:
                try:
                    resp = self._request(
                        'POST', url,
                        json={'email': 'victim@example.com'},
                        headers={'Host': evil_host},
                    )
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)
                    text = getattr(resp, 'text', '')

                    # If server accepts the Host and still sends a success
                    if status == 200 and evil_host in text:
                        findings.append({
                            'technique': 'host_header_reset',
                            'detail': f'Password reset link contains attacker-controlled Host: {evil_host}',
                            'severity': 'critical',
                            'evidence': f'Host: {evil_host} reflected in response at {endpoint}',
                        })
                        return findings
                except Exception:
                    continue
        return findings

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _looks_like_auth_success(text: str) -> bool:
        lower = text.lower()
        indicators = [
            '"success"', '"authenticated"', '"token":', '"access_token"',
            '"jwt":', 'login successful', 'verified', '"valid":true',
        ]
        return any(ind in lower for ind in indicators)

    @staticmethod
    def _extract_token(text: str) -> str:
        """Try to extract a reset token from response text."""
        patterns = [
            re.compile(r'"token"\s*:\s*"([a-zA-Z0-9_-]{6,})"'),
            re.compile(r'"reset_token"\s*:\s*"([a-zA-Z0-9_-]{6,})"'),
            re.compile(r'"code"\s*:\s*"([a-zA-Z0-9_-]{6,})"'),
            re.compile(r'token=([a-zA-Z0-9_-]{6,})'),
        ]
        for p in patterns:
            m = p.search(text)
            if m:
                return m.group(1)
        return ''

    @staticmethod
    def _tokens_are_sequential(tokens: list) -> bool:
        """Check if tokens are sequential (numeric or hex increment)."""
        try:
            nums = [int(t) for t in tokens]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            return len(set(diffs)) == 1
        except (ValueError, TypeError):
            pass
        try:
            nums = [int(t, 16) for t in tokens]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            return len(set(diffs)) == 1 and diffs[0] != 0
        except (ValueError, TypeError):
            pass
        return False
