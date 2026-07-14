"""
Rate Limit Testing Engine — Detection and bypass of rate limiting.

Tests:
  - Rate limit detection
  - Bypass via header rotation (X-Forwarded-For)
  - Bypass via request variation (case, encoding)
  - Bypass via IP rotation (if configured)
  - Bypass via endpoint variation (/api/v1 vs /api/v2)
"""
import logging

logger = logging.getLogger(__name__)

# ── Rate-limited endpoints to test ───────────────────────────────────────────
RATE_LIMITED_ENDPOINTS = [
    '/api/auth/login',
    '/api/login',
    '/api/auth/forgot-password',
    '/api/auth/register',
    '/api/auth/verify-otp',
    '/login',
]

# ── X-Forwarded-For rotation IPs ────────────────────────────────────────────
XFF_IPS = [
    '10.0.0.1',
    '10.0.0.2',
    '192.168.1.100',
    '172.16.0.50',
    '127.0.0.1',
    '8.8.8.8',
]

# ── Request variation transforms ─────────────────────────────────────────────
# Each takes an endpoint and returns a modified version
ENDPOINT_VARIATIONS = [
    lambda e: e.upper(),                         # /API/LOGIN
    lambda e: e + '/',                           # trailing slash
    lambda e: e + '?',                           # trailing question mark
    lambda e: e.replace('/', '/./'),             # dot-segment
    lambda e: e + '#',                           # fragment
    lambda e: e.replace('/api/', '/Api/'),       # case variation
    lambda e: e.replace('/api/', '/api/v1/../'), # path traversal normalise
]

# ── Version variation patterns ───────────────────────────────────────────────
VERSION_VARIATIONS = [
    ('/api/', '/api/v1/'),
    ('/api/', '/api/v2/'),
    ('/api/v1/', '/api/v2/'),
    ('/api/v2/', '/api/v1/'),
]


class RateLimitTester:
    """
    Test rate limiting detection and bypass.

    Usage:
        tester = RateLimitTester(make_request_fn)
        findings = tester.test(url, body, depth='medium')
    """

    def __init__(self, make_request_fn):
        self._request = make_request_fn

    def test(self, url: str, body: str = '', depth: str = 'medium') -> list:
        """
        Run rate limit tests.

        Returns list of finding dicts with keys:
            technique, detail, severity, evidence.
        """
        findings = []
        base = url.rstrip('/')

        # 1. Rate limit detection
        detection = self._detect_rate_limit(base)
        if detection:
            findings.append(detection)

        if depth == 'shallow':
            return findings

        # 2. Header rotation bypass
        findings.extend(self._test_header_bypass(base))

        if depth == 'deep':
            # 3. Request variation bypass
            findings.extend(self._test_request_variation_bypass(base))

            # 4. Endpoint version bypass
            findings.extend(self._test_version_bypass(base))

        return findings

    # ── Rate limit detection ─────────────────────────────────────────────

    def _detect_rate_limit(self, base_url: str) -> dict:
        """Detect if rate limiting is present on sensitive endpoints."""
        payload = {'email': 'test@example.com', 'password': 'test'}
        rapid_count = 10

        for endpoint in RATE_LIMITED_ENDPOINTS:
            url = base_url + endpoint
            blocked = False

            for i in range(rapid_count):
                try:
                    resp = self._request('POST', url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)
                    headers = getattr(resp, 'headers', {})

                    # Common rate limit signals
                    if status == 429:
                        blocked = True
                        break
                    if status == 403 and i > 3:
                        blocked = True
                        break
                    # Rate limit headers
                    for hdr in ('X-RateLimit-Remaining', 'X-Rate-Limit-Remaining',
                                'RateLimit-Remaining', 'Retry-After'):
                        if hdr.lower() in {k.lower() for k in headers}:
                            blocked = True
                            break
                    if blocked:
                        break
                except Exception:
                    continue

            if not blocked:
                return {
                    'technique': 'no_rate_limit',
                    'detail': f'No rate limiting on {endpoint} after {rapid_count} rapid requests',
                    'severity': 'medium',
                    'evidence': f'{rapid_count} requests to {endpoint} without throttling',
                }
        return {}

    # ── Header bypass ────────────────────────────────────────────────────

    def _test_header_bypass(self, base_url: str) -> list:
        """Bypass rate limit using X-Forwarded-For header rotation."""
        findings = []
        payload = {'email': 'test@example.com', 'password': 'test'}

        for endpoint in RATE_LIMITED_ENDPOINTS:
            url = base_url + endpoint

            # First, trigger rate limit
            rate_limited = False
            for _ in range(15):
                try:
                    resp = self._request('POST', url, json=payload)
                    if resp and getattr(resp, 'status_code', 0) == 429:
                        rate_limited = True
                        break
                except Exception:
                    continue

            if not rate_limited:
                continue

            # Now try with different X-Forwarded-For
            for ip in XFF_IPS:
                try:
                    resp = self._request(
                        'POST', url, json=payload,
                        headers={
                            'X-Forwarded-For': ip,
                            'X-Real-IP': ip,
                            'X-Originating-IP': ip,
                        },
                    )
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)

                    if status != 429:
                        findings.append({
                            'technique': 'header_bypass',
                            'detail': f'Rate limit bypassed via X-Forwarded-For: {ip} at {endpoint}',
                            'severity': 'high',
                            'evidence': f'POST {endpoint} with XFF: {ip} → HTTP {status} (was 429)',
                        })
                        return findings
                except Exception:
                    continue
        return findings

    # ── Request variation bypass ─────────────────────────────────────────

    def _test_request_variation_bypass(self, base_url: str) -> list:
        """Bypass rate limit using URL/request variations."""
        findings = []
        payload = {'email': 'test@example.com', 'password': 'test'}

        for endpoint in RATE_LIMITED_ENDPOINTS:
            url = base_url + endpoint

            # Trigger rate limit first
            rate_limited = False
            for _ in range(15):
                try:
                    resp = self._request('POST', url, json=payload)
                    if resp and getattr(resp, 'status_code', 0) == 429:
                        rate_limited = True
                        break
                except Exception:
                    continue

            if not rate_limited:
                continue

            # Try variations
            for variant_fn in ENDPOINT_VARIATIONS:
                varied_endpoint = variant_fn(endpoint)
                varied_url = base_url + varied_endpoint
                try:
                    resp = self._request('POST', varied_url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)

                    if status != 429 and status not in (404, 405):
                        findings.append({
                            'technique': 'variation_bypass',
                            'detail': f'Rate limit bypassed via endpoint variation: {varied_endpoint}',
                            'severity': 'high',
                            'evidence': f'POST {varied_endpoint} → HTTP {status} (original was 429)',
                        })
                        return findings
                except Exception:
                    continue
        return findings

    # ── Endpoint version bypass ──────────────────────────────────────────

    def _test_version_bypass(self, base_url: str) -> list:
        """Bypass rate limit using API version variation."""
        findings = []
        payload = {'email': 'test@example.com', 'password': 'test'}

        for endpoint in RATE_LIMITED_ENDPOINTS:
            url = base_url + endpoint

            # Trigger rate limit
            rate_limited = False
            for _ in range(15):
                try:
                    resp = self._request('POST', url, json=payload)
                    if resp and getattr(resp, 'status_code', 0) == 429:
                        rate_limited = True
                        break
                except Exception:
                    continue

            if not rate_limited:
                continue

            for old, new in VERSION_VARIATIONS:
                if old not in endpoint:
                    continue
                varied = endpoint.replace(old, new)
                varied_url = base_url + varied
                try:
                    resp = self._request('POST', varied_url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)

                    if status != 429 and status not in (404, 405):
                        findings.append({
                            'technique': 'version_bypass',
                            'detail': f'Rate limit bypassed via version variation: {varied}',
                            'severity': 'high',
                            'evidence': f'POST {varied} → HTTP {status} (original was 429)',
                        })
                        return findings
                except Exception:
                    continue
        return findings
