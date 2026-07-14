"""
APIDiscoveryTester — API endpoint discovery and security assessment.
OWASP API Security Top 10 (2023).

Tests for: OpenAPI/Swagger exposure, REST endpoint enumeration, HTTP method
testing (dangerous methods), authentication requirement detection, API versioning
exposure, and rate limiting assessment.
"""
import json
import logging
from urllib.parse import urljoin, urlparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── OpenAPI / Swagger specification paths ────────────────────────────────────
_OPENAPI_PATHS = [
    '/swagger.json', '/swagger.yaml',
    '/swagger-ui.html', '/swagger-ui/',
    '/api-docs', '/api-docs/', '/api-docs.json',
    '/v2/api-docs', '/v3/api-docs',
    '/openapi.json', '/openapi.yaml', '/openapi.yml',
    '/openapi/v3/api-docs',
    '/docs', '/docs/', '/redoc',
    '/.well-known/openapi.json',
    '/api/swagger.json', '/api/openapi.json',
    '/api/v1/swagger.json', '/api/v2/swagger.json',
    '/api/schema', '/api/schema/',
]

# ── Common API base paths to enumerate ───────────────────────────────────────
_API_BASE_PATHS = [
    '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
    '/rest', '/rest/', '/rest/v1', '/rest/v2',
    '/graphql', '/graphiql',
    '/v1', '/v2', '/v3',
    '/json', '/xml',
    '/services', '/service',
    '/ws', '/ws/',
    '/rpc', '/jsonrpc', '/xmlrpc',
]

# ── Common REST resource paths ───────────────────────────────────────────────
_REST_RESOURCES = [
    '/users', '/user', '/accounts', '/account',
    '/admin', '/admins',
    '/profiles', '/profile',
    '/auth', '/login', '/logout', '/register', '/signup',
    '/token', '/tokens', '/refresh',
    '/me', '/self', '/current',
    '/config', '/configuration', '/settings',
    '/health', '/healthcheck', '/health-check', '/status',
    '/metrics', '/stats', '/statistics',
    '/search', '/query',
    '/upload', '/uploads', '/files', '/file',
    '/images', '/image', '/media',
    '/posts', '/articles', '/content',
    '/comments', '/reviews', '/feedback',
    '/orders', '/order', '/cart', '/checkout',
    '/payments', '/payment', '/billing',
    '/notifications', '/messages',
    '/webhooks', '/webhook', '/hooks',
    '/export', '/import', '/backup',
    '/logs', '/log', '/audit',
    '/debug', '/test', '/ping', '/echo',
    '/version', '/info', '/about',
]

# Dangerous HTTP methods
_DANGEROUS_METHODS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']


class APIDiscoveryTester(BaseTester):
    """Discover and assess API endpoints for security issues."""

    TESTER_NAME = 'API Discovery'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        base_url = self._get_base_url(page.url)

        # OpenAPI / Swagger specification exposure
        vulns = self._check_openapi_specs(base_url)
        vulnerabilities.extend(vulns)

        # API base path enumeration
        if depth in ('medium', 'deep'):
            vulns = self._enumerate_api_paths(base_url)
            vulnerabilities.extend(vulns)

        # REST resource enumeration (medium/deep)
        if depth in ('medium', 'deep'):
            api_bases = self._find_api_bases(base_url)
            for api_base in api_bases:
                vulns = self._enumerate_resources(api_base, depth)
                vulnerabilities.extend(vulns)
                if len(vulnerabilities) >= 10:
                    break

        # HTTP method testing on discovered endpoints (deep)
        if depth == 'deep':
            vulns = self._test_dangerous_methods(page, base_url)
            vulnerabilities.extend(vulns)

            # Rate limiting assessment
            vuln = self._test_rate_limiting(page, base_url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_base_url(self, url):
        """Extract base URL from full URL."""
        parsed = urlparse(url)
        return f'{parsed.scheme}://{parsed.netloc}'

    def _check_openapi_specs(self, base_url):
        """Discover exposed OpenAPI/Swagger specification files."""
        vulnerabilities = []

        for path in _OPENAPI_PATHS:
            full_url = urljoin(base_url, path)
            response = self._make_request('GET', full_url, timeout=8)
            if not response or response.status_code != 200:
                continue

            body = response.text or ''
            content_type = response.headers.get('Content-Type', '').lower()

            is_spec = False
            spec_type = 'unknown'

            # JSON spec detection
            if 'json' in content_type or body.strip().startswith('{'):
                try:
                    data = json.loads(body[:50000])
                    if 'swagger' in data or 'openapi' in data:
                        is_spec = True
                        spec_type = f"OpenAPI {data.get('openapi', data.get('swagger', 'unknown'))}"
                    elif 'paths' in data or 'definitions' in data:
                        is_spec = True
                        spec_type = 'OpenAPI (inferred)'
                except (json.JSONDecodeError, ValueError):
                    pass

            # YAML spec detection
            if not is_spec and ('yaml' in content_type or 'yml' in path):
                if 'swagger:' in body[:500] or 'openapi:' in body[:500]:
                    is_spec = True
                    spec_type = 'OpenAPI (YAML)'

            # Swagger UI detection
            if not is_spec and ('swagger-ui' in path or 'swagger' in body.lower()[:2000]):
                if '<div id="swagger-ui">' in body or 'SwaggerUIBundle' in body:
                    is_spec = True
                    spec_type = 'Swagger UI'

            if is_spec:
                # Count endpoints if parseable
                endpoint_count = 0
                try:
                    data = json.loads(body[:100000])
                    endpoint_count = len(data.get('paths', {}))
                except Exception:
                    pass

                vulnerabilities.append(self._build_vuln(
                    name=f'API Specification Exposed: {path}',
                    severity='medium',
                    category='API Discovery',
                    description=f'{spec_type} specification found at "{path}". '
                               f'{"It defines " + str(endpoint_count) + " endpoint(s)." if endpoint_count else ""} '
                               f'Exposed API specs reveal all endpoints, parameters, '
                               f'authentication schemes, and data models.',
                    impact='Attackers gain a complete map of the API surface including '
                          'hidden/internal endpoints, expected parameters, and data types. '
                          'This dramatically accelerates targeted attacks.',
                    remediation='Restrict API spec access to authenticated developers only. '
                               'Disable Swagger UI in production. Use API gateway access controls.',
                    cwe='CWE-200',
                    cvss=5.3,
                    affected_url=full_url,
                    evidence=f'Spec type: {spec_type}\n'
                            f'Endpoints: {endpoint_count}\n'
                            f'Path: {path}',
                ))
                break  # One spec is enough

        return vulnerabilities

    def _find_api_bases(self, base_url):
        """Find active API base paths."""
        api_bases = []
        for path in _API_BASE_PATHS[:8]:
            full_url = urljoin(base_url, path)
            response = self._make_request('GET', full_url, timeout=5)
            if response and response.status_code in (200, 401, 403, 405):
                api_bases.append(full_url.rstrip('/'))
                if len(api_bases) >= 3:
                    break
        return api_bases if api_bases else [base_url.rstrip('/') + '/api']

    def _enumerate_api_paths(self, base_url):
        """Enumerate common API base paths."""
        vulnerabilities = []
        found_apis = []

        for path in _API_BASE_PATHS:
            full_url = urljoin(base_url, path)
            response = self._make_request('GET', full_url, timeout=5)
            if not response:
                continue

            if response.status_code in (200, 401, 403, 405):
                content_type = response.headers.get('Content-Type', '').lower()
                is_api = ('json' in content_type or 'xml' in content_type or
                         response.status_code in (401, 405))
                if is_api:
                    found_apis.append({
                        'path': path,
                        'status': response.status_code,
                        'auth_required': response.status_code == 401,
                    })

        if found_apis:
            unauthenticated = [a for a in found_apis if not a['auth_required'] and a['status'] == 200]
            if unauthenticated:
                vulnerabilities.append(self._build_vuln(
                    name='API Endpoints Without Authentication',
                    severity='medium',
                    category='API Discovery',
                    description=f'{len(unauthenticated)} API endpoint(s) respond without '
                               f'requiring authentication.',
                    impact='Unauthenticated API endpoints may expose sensitive data or allow '
                          'unauthorized operations.',
                    remediation='Require authentication on all API endpoints. '
                               'Use API keys, OAuth 2.0, or JWT tokens.',
                    cwe='CWE-306',
                    cvss=5.3,
                    affected_url=base_url,
                    evidence='Unauthenticated API paths:\n' +
                            '\n'.join(f"  - {a['path']} (HTTP {a['status']})"
                                     for a in unauthenticated[:10]),
                ))

        return vulnerabilities

    def _enumerate_resources(self, api_base, depth):
        """Enumerate REST resources under an API base path."""
        vulnerabilities = []
        resources = _REST_RESOURCES[:20] if depth == 'medium' else _REST_RESOURCES
        accessible = []

        for resource in resources:
            full_url = api_base + resource
            response = self._make_request('GET', full_url, timeout=5)
            if not response:
                continue

            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                body = response.text or ''

                # Data exposure check — does the endpoint return actual data?
                has_data = False
                if 'json' in content_type:
                    try:
                        data = json.loads(body[:10000])
                        if isinstance(data, (list, dict)) and data:
                            has_data = True
                    except (json.JSONDecodeError, ValueError):
                        pass

                sensitive = any(kw in resource for kw in
                              ['/users', '/admin', '/config', '/settings',
                               '/logs', '/debug', '/backup', '/export'])

                if has_data and sensitive:
                    accessible.append({
                        'path': resource,
                        'sensitive': sensitive,
                        'size': len(body),
                    })

        if accessible:
            critically_sensitive = [r for r in accessible if r['sensitive']]
            if critically_sensitive:
                vulnerabilities.append(self._build_vuln(
                    name='Sensitive API Resources Accessible Without Auth',
                    severity='high',
                    category='API Discovery',
                    description=f'{len(critically_sensitive)} sensitive API resource(s) '
                               f'return data without authentication.',
                    impact='Sensitive endpoints expose user data, admin configurations, '
                          'logs, or backup data to unauthenticated users.',
                    remediation='Implement proper authentication and authorization on all '
                               'API endpoints. Follow OWASP API Security Top 10 guidelines.',
                    cwe='CWE-306',
                    cvss=7.5,
                    affected_url=api_base,
                    evidence='Accessible sensitive resources:\n' +
                            '\n'.join(f"  - {r['path']} ({r['size']} bytes)"
                                     for r in critically_sensitive[:10]),
                ))

        return vulnerabilities

    def _test_dangerous_methods(self, page, base_url):
        """Test for dangerous HTTP methods on discovered endpoints."""
        vulnerabilities = []

        # Test on the current page and API paths
        test_urls = [page.url]
        for path in ['/api', '/api/v1', '/api/v2']:
            test_urls.append(urljoin(base_url, path))

        dangerous_found = []

        for test_url in test_urls:
            # Use OPTIONS to discover allowed methods
            response = self._make_request('OPTIONS', test_url, timeout=5)
            if response:
                allow = response.headers.get('Allow', '')
                access_methods = response.headers.get('Access-Control-Allow-Methods', '')
                methods_str = f'{allow},{access_methods}'.upper()

                for method in _DANGEROUS_METHODS:
                    if method in methods_str:
                        dangerous_found.append(f'{method} on {test_url}')

            # Also test TRACE directly
            trace_resp = self._make_request('TRACE', test_url, timeout=5)
            if trace_resp and trace_resp.status_code == 200:
                if 'TRACE' in (trace_resp.text or '').upper()[:500]:
                    dangerous_found.append(f'TRACE (active) on {test_url}')

        if dangerous_found:
            has_trace = any('TRACE' in d for d in dangerous_found)
            vulnerabilities.append(self._build_vuln(
                name='Dangerous HTTP Methods Enabled',
                severity='medium' if not has_trace else 'high',
                category='API Discovery',
                description=f'{len(dangerous_found)} dangerous HTTP method(s) detected '
                           f'across tested endpoints.',
                impact='TRACE enables Cross-Site Tracing (XST) attacks. PUT/DELETE without '
                      'auth allows data modification. CONNECT can proxy connections.',
                remediation='Disable TRACE, CONNECT methods globally. '
                           'Restrict PUT/DELETE/PATCH to authenticated, authorized requests. '
                           'Configure AllowedMethods in web server.',
                cwe='CWE-749',
                cvss=5.3,
                affected_url=base_url,
                evidence='Dangerous methods found:\n' +
                        '\n'.join(f'  - {d}' for d in dangerous_found[:10]),
            ))

        return vulnerabilities

    def _test_rate_limiting(self, page, base_url):
        """Quick rate limiting assessment on API endpoints."""
        # Send rapid requests and check if any rate limiting kicks in
        api_url = urljoin(base_url, '/api')
        response = self._make_request('GET', api_url, timeout=5)
        if not response or response.status_code == 404:
            api_url = page.url

        rate_limited = False
        for _ in range(10):
            resp = self._make_request('GET', api_url, timeout=3)
            if resp and resp.status_code == 429:
                rate_limited = True
                break

        # Check for rate limit headers
        rate_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining',
                       'RateLimit-Limit', 'Retry-After', 'X-Rate-Limit']
        has_rate_headers = False
        if response:
            has_rate_headers = any(response.headers.get(h) for h in rate_headers)

        if not rate_limited and not has_rate_headers:
            return self._build_vuln(
                name='No API Rate Limiting Detected',
                severity='low',
                category='API Discovery',
                description='No rate limiting mechanism was detected after sending '
                           'rapid requests. No rate limit headers were found.',
                impact='Without rate limiting, APIs are vulnerable to brute-force attacks, '
                      'credential stuffing, enumeration, and denial of service.',
                remediation='Implement rate limiting using API gateway or middleware. '
                           'Return X-RateLimit-* headers. Use sliding window or token bucket '
                           'algorithms. Set different limits for authenticated/anonymous users.',
                cwe='CWE-770',
                cvss=4.3,
                affected_url=api_url,
                evidence='No rate limiting detected after 10 rapid requests.\n'
                        'No rate limit headers found in response.',
            )
        return None
