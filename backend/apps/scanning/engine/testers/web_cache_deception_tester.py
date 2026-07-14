"""
Web Cache Deception Tester — Detects web cache deception vulnerabilities.

Covers:
  - Path confusion (append .css/.js to authenticated URLs)
  - Cache poisoning via unkeyed headers
  - Cache key normalization exploitation
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Sensitive URL patterns (likely authenticated) ────────────────────────────
SENSITIVE_URL_PATTERNS = [
    r'/account', r'/profile', r'/dashboard', r'/settings',
    r'/admin', r'/user', r'/my[_-]', r'/me\b', r'/billing',
    r'/api/me', r'/api/user', r'/api/account',
]

# ── Static extensions to append for cache deception ──────────────────────────
CACHE_DECEPTION_EXTENSIONS = [
    '.css', '.js', '.png', '.jpg', '.gif', '.ico',
    '.svg', '.woff', '.woff2', '.ttf',
]

# ── Unkeyed header candidates for cache poisoning ────────────────────────────
UNKEYED_HEADERS = [
    ('X-Forwarded-Host', 'evil.example.com'),
    ('X-Forwarded-Scheme', 'nothttps'),
    ('X-Original-URL', '/evil-path'),
    ('X-Rewrite-URL', '/evil-path'),
    ('X-Forwarded-Port', '1337'),
]

# ── Cache indicators in response headers ─────────────────────────────────────
CACHE_HIT_PATTERNS = [
    re.compile(r'x-cache:\s*hit', re.IGNORECASE),
    re.compile(r'cf-cache-status:\s*hit', re.IGNORECASE),
    re.compile(r'x-varnish', re.IGNORECASE),
    re.compile(r'age:\s*[1-9]', re.IGNORECASE),
    re.compile(r'x-cache-lookup:\s*hit', re.IGNORECASE),
]

# ── Sensitive data patterns in response ──────────────────────────────────────
SENSITIVE_DATA_PATTERNS = [
    re.compile(r'email["\s:=]+[^@\s]+@[^@\s]+', re.IGNORECASE),
    re.compile(r'(api[_-]?key|token|session|secret)["\s:=]+\S{8,}', re.IGNORECASE),
    re.compile(r'(password|passwd|pwd)["\s:=]+\S+', re.IGNORECASE),
]


class WebCacheDeceptionTester(BaseTester):
    """Test for web cache deception vulnerabilities."""

    TESTER_NAME = 'Web Cache Deception'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        headers = getattr(page, 'headers', {}) or {}

        is_sensitive = self._is_sensitive_url(url)

        # 1. Test path confusion (append static extensions)
        if is_sensitive:
            vuln = self._test_path_confusion(url, body, headers)
            if vuln:
                vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Test cache poisoning via unkeyed headers
        vuln = self._test_unkeyed_header_poisoning(url, headers)
        if vuln:
            vulns.append(vuln)

        if depth == 'deep':
            # 3. Test cache key normalization
            vuln = self._test_cache_key_normalization(url, body)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_sensitive_url(self, url: str) -> bool:
        for pattern in SENSITIVE_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _has_cache_indicators(self, resp_headers: dict) -> bool:
        header_str = '\n'.join(f'{k}: {v}' for k, v in resp_headers.items())
        return any(p.search(header_str) for p in CACHE_HIT_PATTERNS)

    def _has_sensitive_data(self, body: str) -> bool:
        return any(p.search(body) for p in SENSITIVE_DATA_PATTERNS)

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _test_path_confusion(self, url: str, orig_body: str,
                             orig_headers: dict):
        """Append static extensions to authenticated URLs and check caching."""
        for ext in CACHE_DECEPTION_EXTENSIONS[:3]:
            test_url = url.rstrip('/') + '/nonexistent' + ext
            try:
                resp = self._make_request('GET', test_url)
                if not resp or resp.status_code not in (200, 301, 302):
                    continue

                dict(getattr(resp, 'headers', {}))
                resp_body = getattr(resp, 'text', '')

                # Vulnerability: sensitive data returned on a cacheable path
                if self._has_sensitive_data(resp_body):
                    # Second request to confirm caching
                    resp2 = self._make_request('GET', test_url)
                    if resp2 and self._has_cache_indicators(
                            dict(getattr(resp2, 'headers', {}))):
                        return self._build_vuln(
                            name='Web Cache Deception',
                            severity='high',
                            category='Security Misconfiguration',
                            description=(
                                f'Appending "{ext}" to the URL causes the server '
                                'to return sensitive data on a cacheable path. '
                                'An attacker can trick a victim into visiting this '
                                'URL, caching their private data.'
                            ),
                            impact='Exposure of authenticated user data, session hijacking',
                            remediation=(
                                'Configure cache to key on full URL path. '
                                'Disable caching for authenticated responses. '
                                'Use Cache-Control: no-store for sensitive pages.'
                            ),
                            cwe='CWE-525',
                            cvss=7.5,
                            affected_url=test_url,
                            evidence=f'Sensitive data returned on cacheable path {ext}',
                        )

                # Even without cache confirmation — if sensitive data leaks
                if self._has_sensitive_data(resp_body):
                    return self._build_vuln(
                        name='Web Cache Deception',
                        severity='medium',
                        category='Security Misconfiguration',
                        description=(
                            f'Appending "{ext}" to the URL still returns '
                            'sensitive data. If a CDN/proxy caches this response, '
                            'private data may be exposed to attackers.'
                        ),
                        impact='Potential exposure of authenticated user data',
                        remediation=(
                            'Return 404 for non-existent static resources. '
                            'Use Cache-Control: no-store for sensitive pages.'
                        ),
                        cwe='CWE-525',
                        cvss=6.5,
                        affected_url=test_url,
                        evidence=f'Sensitive data on static-extension path: {ext}',
                    )
            except Exception:
                continue
        return None

    def _test_unkeyed_header_poisoning(self, url: str, orig_headers: dict):
        """Test if unkeyed headers change the cached response."""
        for header_name, header_value in UNKEYED_HEADERS[:3]:
            try:
                resp = self._make_request(
                    'GET', url,
                    headers={header_name: header_value},
                )
                if not resp:
                    continue

                resp_body = getattr(resp, 'text', '')
                resp_headers = dict(getattr(resp, 'headers', {}))

                # Check if our injected value appears in response
                if header_value in resp_body or header_value in str(resp_headers):
                    return self._build_vuln(
                        name='Cache Poisoning via Unkeyed Header',
                        severity='high',
                        category='Security Misconfiguration',
                        description=(
                            f'The header "{header_name}" is reflected in the '
                            'response but may not be part of the cache key. '
                            'An attacker can poison the cache to serve '
                            'malicious content to other users.'
                        ),
                        impact='Cache poisoning, XSS via cached response, phishing',
                        remediation=(
                            f'Include "{header_name}" in the cache key or '
                            'strip it before processing. Use Vary header.'
                        ),
                        cwe='CWE-444',
                        cvss=7.5,
                        affected_url=url,
                        evidence=f'{header_name}: {header_value} reflected in response',
                    )
            except Exception:
                continue
        return None

    def _test_cache_key_normalization(self, url: str, orig_body: str):
        """Test cache key normalization issues."""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)

        # Test path normalization: /path vs /Path vs /PATH
        original_path = parsed.path
        if not original_path or original_path == '/':
            return None

        variations = [
            original_path.upper(),
            original_path + '/',
            original_path + '%20',
        ]

        try:
            resp_orig = self._make_request('GET', url)
            if not resp_orig:
                return None
            orig_body = getattr(resp_orig, 'text', '')

            for variant in variations:
                test_url = urlunparse(parsed._replace(path=variant))
                resp = self._make_request('GET', test_url)
                if not resp:
                    continue

                resp_body = getattr(resp, 'text', '')
                # Same content but different path → normalization issue
                if (resp.status_code == 200
                        and len(resp_body) > 50
                        and abs(len(resp_body) - len(orig_body)) < 100):
                    return self._build_vuln(
                        name='Cache Key Normalization Issue',
                        severity='medium',
                        category='Security Misconfiguration',
                        description=(
                            f'Path variation "{variant}" returns the same '
                            'content as the original path. This normalization '
                            'may allow cache key collisions.'
                        ),
                        impact='Cache poisoning via path normalization',
                        remediation=(
                            'Ensure the cache normalizes paths consistently. '
                            'Redirect non-canonical URLs to canonical form.'
                        ),
                        cwe='CWE-436',
                        cvss=5.3,
                        affected_url=test_url,
                        evidence=f'Path "{variant}" returns same content as "{original_path}"',
                    )
        except Exception:
            pass
        return None
