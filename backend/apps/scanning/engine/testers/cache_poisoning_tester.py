"""
CachePoisoningTester — Web Cache Poisoning detection.
OWASP A05:2021 — Security Misconfiguration.

Tests for: unkeyed header injection, cache key manipulation,
web cache deception, host header cache poisoning,
and parameter cloaking.
"""
import time
import logging
import hashlib
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Headers commonly unkeyed in caches
UNKEYED_HEADERS = [
    ('X-Forwarded-Host', 'evil-cache-test.example.com'),
    ('X-Forwarded-Scheme', 'nothttps'),
    ('X-Forwarded-Proto', 'nothttps'),
    ('X-Original-URL', '/cache-test-payload'),
    ('X-Rewrite-URL', '/cache-test-payload'),
    ('X-Host', 'evil-cache-test.example.com'),
    ('X-Forwarded-Port', '1337'),
    ('X-Forwarded-Prefix', '/cache-test'),
    ('Forwarded', 'host=evil-cache-test.example.com'),
    ('CF-Connecting-IP', '127.0.0.1'),
    ('True-Client-IP', '127.0.0.1'),
    ('X-Custom-IP-Authorization', '127.0.0.1'),
]

# Common static file extensions for cache deception
STATIC_EXTENSIONS = [
    '.css', '.js', '.png', '.jpg', '.gif', '.ico',
    '.svg', '.woff', '.woff2', '.ttf', '.json',
]

# Cache indicators in response headers
CACHE_HIT_HEADERS = {
    'X-Cache': ['hit', 'miss'],
    'CF-Cache-Status': ['hit', 'miss', 'dynamic', 'expired'],
    'X-Cache-Status': ['hit', 'miss'],
    'Age': None,
    'X-Varnish': None,
    'Via': None,
    'X-CDN': None,
    'X-Fastly-Request-ID': None,
    'X-Served-By': None,
}


class CachePoisoningTester(BaseTester):
    """Test for web cache poisoning vulnerabilities."""

    TESTER_NAME = 'Cache Poisoning'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # 1. Detect cache presence
        cache_info = self._detect_cache(page)

        # 2. Test unkeyed header injection
        vulns = self._test_unkeyed_headers(page, cache_info, depth)
        vulnerabilities.extend(vulns)

        # 3. Test web cache deception
        if depth in ('medium', 'deep'):
            vuln = self._test_cache_deception(page)
            if vuln:
                vulnerabilities.append(vuln)

        # 4. Test parameter cloaking (deep only)
        if depth == 'deep':
            vuln = self._test_parameter_cloaking(page)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_cache(self, page) -> dict:
        """Detect if a caching layer is present."""
        info = {
            'has_cache': False,
            'cache_type': 'unknown',
            'headers': {},
        }

        try:
            response = self._make_request('GET', page.url)
        except Exception:
            return info

        if not response:
            return info

        for header_name, expected_values in CACHE_HIT_HEADERS.items():
            value = response.headers.get(header_name)
            if value:
                info['has_cache'] = True
                info['headers'][header_name] = value

                if header_name == 'X-Cache' and 'varnish' in value.lower():
                    info['cache_type'] = 'Varnish'
                elif header_name == 'CF-Cache-Status':
                    info['cache_type'] = 'Cloudflare'
                elif header_name == 'X-Fastly-Request-ID':
                    info['cache_type'] = 'Fastly'

        # Check Cache-Control header
        cc = response.headers.get('Cache-Control', '')
        if 'public' in cc or 's-maxage' in cc:
            info['has_cache'] = True

        return info

    def _test_unkeyed_headers(self, page, cache_info: dict, depth: str) -> list:
        """Test for unkeyed headers that can poison the cache."""
        vulnerabilities = []

        # Use a cache buster to get clean responses
        buster = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        separator = '&' if '?' in page.url else '?'
        base_url = f'{page.url}{separator}cb={buster}'

        # Get baseline response
        try:
            baseline = self._make_request('GET', base_url)
        except Exception:
            return vulnerabilities

        if not baseline:
            return vulnerabilities

        baseline_body = baseline.text

        headers_to_test = UNKEYED_HEADERS[:5] if depth == 'shallow' else UNKEYED_HEADERS

        for header_name, header_value in headers_to_test:
            # Fresh cache buster for each test
            buster = hashlib.md5(f'{header_name}{time.time()}'.encode()).hexdigest()[:8]
            test_url = f'{page.url}{separator}cb={buster}'

            try:
                # Send poisoned request
                poisoned_response = self._make_request(
                    'GET', test_url,
                    headers={header_name: header_value},
                )
            except Exception:
                continue

            if not poisoned_response:
                continue

            poisoned_body = poisoned_response.text

            # Check if the injected value appears in the response
            if header_value in poisoned_body and header_value not in baseline_body:
                # Verify it's cached by requesting again without the header
                time.sleep(0.5)
                try:
                    verify = self._make_request('GET', test_url)
                except Exception:
                    continue

                is_cached = verify and header_value in verify.text

                severity = 'high' if is_cached else 'medium'
                cvss = 7.5 if is_cached else 5.3

                vulnerabilities.append(self._build_vuln(
                    name=f'Unkeyed Header Reflected: {header_name}',
                    severity=severity,
                    category='Cache Poisoning',
                    description=f'The header "{header_name}" is reflected in the response but '
                               f'likely not included in the cache key. '
                               f'{"The poisoned response was verified to be cached." if is_cached else "Cache persistence could not be confirmed."}',
                    impact='An attacker can inject malicious content via unkeyed headers, '
                          'and the poisoned response will be served to other users from the cache.',
                    remediation='Include all security-relevant headers in the cache key. '
                               'Use Vary header to vary on custom headers. '
                               'Configure cache to strip or ignore forwarded headers.',
                    cwe='CWE-444',
                    cvss=cvss,
                    affected_url=page.url,
                    evidence=f'Header: {header_name}: {header_value}\n'
                            f'Value reflected in response: Yes\n'
                            f'Cached: {"Yes" if is_cached else "Uncertain"}',
                ))

                if is_cached:
                    break  # Critical finding, no need for more

        return vulnerabilities

    def _test_cache_deception(self, page) -> object:
        """Test for web cache deception vulnerability."""
        from urllib.parse import urlparse

        parsed = urlparse(page.url)
        path = parsed.path.rstrip('/')

        if not path or path == '/':
            return None

        for ext in STATIC_EXTENSIONS[:5]:
            # Append static extension to path
            deception_path = f'{path}/nonexistent{ext}'
            deception_url = f'{parsed.scheme}://{parsed.netloc}{deception_path}'
            if parsed.query:
                deception_url += f'?{parsed.query}'

            try:
                response = self._make_request('GET', deception_url)
            except Exception:
                continue

            if not response or response.status_code != 200:
                continue

            # Check if dynamic content is returned (page doesn't 404)
            body = response.text
            if len(body) < 100:
                continue

            # Check cache headers
            cache_control = response.headers.get('Cache-Control', '')
            x_cache = response.headers.get('X-Cache', '')
            age = response.headers.get('Age', '')

            is_cached = ('hit' in x_cache.lower() or
                         'public' in cache_control.lower() or
                         age.isdigit())

            if is_cached:
                return self._build_vuln(
                    name='Web Cache Deception',
                    severity='high',
                    category='Cache Poisoning',
                    description=f'The application serves dynamic content when a static file extension '
                               f'is appended to the URL path (e.g., {deception_path}). The response '
                               f'is then cached, allowing attackers to read other users\' data.',
                    impact='Attackers can trick users into visiting a crafted URL that caches their '
                          'personal/sensitive data, which the attacker then retrieves from the cache.',
                    remediation='Configure cache to respect the origin Content-Type header. '
                               'Use path-based routing that returns 404 for non-existent paths. '
                               'Set Cache-Control: no-store on dynamic pages.',
                    cwe='CWE-525',
                    cvss=7.5,
                    affected_url=deception_url,
                    evidence=f'Path: {deception_path}\n'
                            f'Status: {response.status_code}\n'
                            f'Cache-Control: {cache_control}\n'
                            f'X-Cache: {x_cache}\nAge: {age}',
                )

        return None

    def _test_parameter_cloaking(self, page) -> object:
        """Test for parameter cloaking via query string separators."""
        from urllib.parse import urlparse

        urlparse(page.url)

        # Try different parameter separators
        separators = [';', '&', '%26', '%3b']
        canary = 'cachepoisontest123'

        for sep in separators:
            test_url = f'{page.url}{"&" if "?" in page.url else "?"}test={canary}{sep}utm_content={canary}'

            try:
                response = self._make_request('GET', test_url)
            except Exception:
                continue

            if response and canary in response.text:
                # Check if cache treats the separator differently
                cache_status = response.headers.get('X-Cache', '') or \
                              response.headers.get('CF-Cache-Status', '')

                if 'hit' in cache_status.lower():
                    return self._build_vuln(
                        name='Parameter Cloaking in Cache',
                        severity='medium',
                        category='Cache Poisoning',
                        description=f'The application and cache interpret parameter separators '
                                   f'differently ("{sep}" separator). This allows parameter '
                                   f'cloaking attacks.',
                        impact='Attackers can inject unkeyed parameters that are processed by '
                              'the application but ignored by the cache.',
                        remediation='Ensure the cache and application use the same parameter '
                                   'parsing logic. Normalize query strings before caching.',
                        cwe='CWE-444',
                        cvss=5.3,
                        affected_url=test_url,
                        evidence=f'Separator: {sep}\nCanary reflected and response cached.',
                    )

        return None
