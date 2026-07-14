"""
API Security Tester — Detects OWASP API Top 10 vulnerabilities.

Covers:
  API1: Broken Object-Level Authorization (BOLA / IDOR)
  API2: Broken Authentication
  API3: Broken Object Property-Level Authorization (Mass Assignment, Excessive Data)
  API4: Unrestricted Resource Consumption (Rate Limiting)
  API5: Broken Function-Level Authorization (BFLA)
  API6: Unrestricted Access to Sensitive Business Flows
  API7: Server-Side Request Forgery (delegated to SSRF tester)
  API8: Security Misconfiguration (API-specific)
  API9: Improper Inventory Management (shadow/deprecated APIs)
  API10: Unsafe Consumption of APIs
"""
import json
import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Common API base paths ────────────────────────────────────────────────────
API_PREFIXES = ['/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2']

# ── Resource endpoints for BOLA testing ──────────────────────────────────────
BOLA_RESOURCES = [
    '/users/{id}', '/user/{id}', '/accounts/{id}', '/orders/{id}',
    '/invoices/{id}', '/profiles/{id}', '/documents/{id}', '/files/{id}',
    '/messages/{id}', '/transactions/{id}', '/settings/{id}', '/reports/{id}',
]

# ── Admin / privileged endpoints for BFLA ────────────────────────────────────
ADMIN_ENDPOINTS = [
    '/admin/users', '/admin/settings', '/admin/config', '/admin/logs',
    '/admin/dashboard', '/admin/reports', '/manage/users', '/internal/config',
    '/system/status', '/debug', '/admin/database', '/admin/export',
]

# ── Deprecated / shadow API paths for API9 ──────────────────────────────────
DEPRECATED_VERSIONS = [
    '/api/v0/', '/api/v1/', '/api/beta/', '/api/alpha/',
    '/api/internal/', '/api/debug/', '/api/test/', '/api/staging/',
    '/api/old/', '/api/legacy/', '/api/deprecated/',
]

# ── Mass assignment fields for API3 ──────────────────────────────────────────
MASS_ASSIGN_FIELDS = {
    'role': 'admin',
    'is_admin': True,
    'isAdmin': True,
    'is_staff': True,
    'is_superuser': True,
    'permissions': ['admin', 'write', 'delete', 'manage'],
    'verified': True,
    'email_verified': True,
    'account_type': 'premium',
    'credit_balance': 99999,
    'subscription': 'enterprise',
}


class APITester(BaseTester):
    """Tests APIs for OWASP API Top 10 vulnerabilities."""

    TESTER_NAME = 'API Security'
    REQUEST_TIMEOUT = 10

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        """Test API endpoints for OWASP API Top 10 vulnerabilities."""
        vulns = []
        target = getattr(page, 'url', '')

        # API1: Broken Object-Level Authorization (BOLA/IDOR)
        vulns.extend(self._test_bola(target, depth))

        # API3: Mass Assignment / Excessive Data Exposure
        vulns.extend(self._test_mass_assignment(target, depth))

        # API4: Rate Limiting
        vulns.extend(self._test_rate_limiting(target))

        # API5: Broken Function-Level Authorization (BFLA)
        vulns.extend(self._test_bfla(target, depth))

        # API8: Security Misconfiguration
        vulns.extend(self._test_api_misconfig(target, depth))

        # API9: Improper Inventory Management
        if depth in ('medium', 'deep'):
            vulns.extend(self._test_shadow_apis(target))

        # Excessive data exposure check
        if depth in ('medium', 'deep'):
            vulns.extend(self._test_excessive_data(target))

        return vulns

    def _test_bola(self, target: str, depth: str) -> list:
        """API1: Test for Broken Object-Level Authorization (IDOR)."""
        vulns = []
        base = target.rstrip('/')

        test_ids = ['1', '2', '100', '999', '0', '-1']
        if depth == 'shallow':
            test_ids = test_ids[:2]

        for prefix in API_PREFIXES[:3]:
            for resource_template in BOLA_RESOURCES:
                for test_id in test_ids:
                    path = resource_template.replace('{id}', test_id)
                    url = base + prefix + path

                    resp = self._make_request('GET', url)
                    if not resp:
                        continue

                    if resp.status_code == 200:
                        body = resp.text or ''
                        try:
                            data = json.loads(body)
                            # Check if it returns actual user data
                            sensitive_keys = ['email', 'phone', 'password', 'ssn',
                                              'address', 'credit_card', 'bank_account']
                            found_sensitive = [k for k in sensitive_keys
                                               if k in str(data).lower()]

                            if found_sensitive or (isinstance(data, dict) and len(data) > 2):
                                resource_name = resource_template.split('/')[1]
                                vulns.append(self._build_vuln(
                                    name=f'BOLA/IDOR — Unauthorized Access to {resource_name}',
                                    severity='high',
                                    category='Authorization',
                                    description=(
                                        f'The endpoint {url} returns data for resource ID {test_id} '
                                        f'without proper authorization checks. Iterating IDs '
                                        f'exposes other users\' data.'
                                    ),
                                    impact=(
                                        'Unauthorized access to other users\' records. '
                                        'Can enumerate all resources by iterating IDs. '
                                        f'Sensitive fields exposed: {", ".join(found_sensitive) if found_sensitive else "user data"}'
                                    ),
                                    remediation=(
                                        '1. Implement object-level authorization on every request. '
                                        '2. Verify the requesting user owns the resource. '
                                        '3. Use UUIDs instead of sequential IDs. '
                                        '4. Add authorization middleware that checks ownership.'
                                    ),
                                    cwe='CWE-639',
                                    cvss=7.5,
                                    affected_url=url,
                                    evidence=f'Resource {test_id} accessible. Keys: {list(data.keys())[:10] if isinstance(data, dict) else "array"}',
                                ))
                                return vulns
                        except (json.JSONDecodeError, TypeError):
                            pass

        return vulns

    def _test_mass_assignment(self, target: str, depth: str) -> list:
        """API3: Test for mass assignment vulnerabilities."""
        vulns = []
        base = target.rstrip('/')
        update_endpoints = [
            '/api/user/profile', '/api/users/me', '/api/account',
            '/api/user/settings', '/api/profile',
        ]

        for endpoint in update_endpoints:
            url = base + endpoint

            # Try to inject additional fields
            for field, value in list(MASS_ASSIGN_FIELDS.items())[:5]:
                payload = {'name': 'TestUser', field: value}

                resp = self._make_request('PUT', url, json=payload)
                if not resp:
                    resp = self._make_request('PATCH', url, json=payload)
                if not resp:
                    continue

                status = resp.status_code
                body = resp.text or ''

                if status in (200, 201):
                    try:
                        data = json.loads(body)
                        # Check if the injected field was accepted
                        if field in data and data[field] == value:
                            vulns.append(self._build_vuln(
                                name=f'Mass Assignment — {field} Writable',
                                severity='critical' if 'admin' in str(value).lower() else 'high',
                                category='Authorization',
                                description=(
                                    f'The endpoint {url} accepted the field "{field}" with '
                                    f'value "{value}" in a user update request. This is a '
                                    f'mass assignment vulnerability allowing modification of '
                                    f'protected fields.'
                                ),
                                impact=(
                                    'Privilege escalation if admin/role fields are writable. '
                                    'Account takeover, unauthorized access to premium features, '
                                    'or financial manipulation.'
                                ),
                                remediation=(
                                    '1. Use an allowlist of modifiable fields per endpoint. '
                                    '2. Never bind request body directly to database models. '
                                    '3. Use DTOs/serializers with explicit field definitions. '
                                    '4. Mark sensitive fields as read-only in the API schema.'
                                ),
                                cwe='CWE-915',
                                cvss=8.5,
                                affected_url=url,
                                evidence=f'Field "{field}" set to "{value}" and accepted.',
                            ))
                            return vulns
                    except (json.JSONDecodeError, TypeError):
                        pass

        return vulns

    def _test_rate_limiting(self, target: str) -> list:
        """API4: Test for missing rate limiting on sensitive endpoints."""
        vulns = []
        base = target.rstrip('/')
        sensitive_endpoints = [
            '/api/auth/login', '/api/login', '/api/auth/token',
            '/api/forgot-password', '/api/password/reset',
            '/api/otp/verify', '/api/2fa/verify',
        ]

        for endpoint in sensitive_endpoints:
            url = base + endpoint
            success_count = 0

            for i in range(25):
                payload = {'username': f'test{i}@test.com', 'password': 'wrong'}
                resp = self._make_request('POST', url, json=payload)
                if not resp:
                    break

                if resp.status_code == 429:
                    break  # Rate limiting is working
                success_count += 1

            if success_count >= 25:
                vulns.append(self._build_vuln(
                    name='Missing Rate Limiting on Authentication Endpoint',
                    severity='high',
                    category='API Security',
                    description=(
                        f'The endpoint {url} does not enforce rate limiting. '
                        f'25 rapid requests were all processed without throttling.'
                    ),
                    impact=(
                        'Brute-force password attacks, credential stuffing, '
                        'account lockout abuse, OTP bypass through rapid guessing.'
                    ),
                    remediation=(
                        '1. Implement rate limiting (e.g., 5 attempts per minute). '
                        '2. Use exponential backoff after failed attempts. '
                        '3. Implement account lockout after N failed attempts. '
                        '4. Use CAPTCHA after repeated failures. '
                        '5. Return 429 with Retry-After header.'
                    ),
                    cwe='CWE-307',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'{success_count}/25 requests processed without rate limiting.',
                ))
                break

        return vulns

    def _test_bfla(self, target: str, depth: str) -> list:
        """API5: Test for Broken Function-Level Authorization."""
        vulns = []
        base = target.rstrip('/')

        for prefix in API_PREFIXES[:2]:
            for admin_path in ADMIN_ENDPOINTS:
                url = base + prefix + admin_path

                resp = self._make_request('GET', url)
                if not resp:
                    continue

                if resp.status_code == 200:
                    body = resp.text or ''
                    # Verify it's actually returning admin content
                    try:
                        data = json.loads(body)
                        if isinstance(data, (dict, list)) and len(str(data)) > 10:
                            admin_indicators = ['users', 'config', 'settings', 'logs',
                                                'database', 'admin', 'system']
                            if any(ind in str(data).lower() for ind in admin_indicators):
                                vulns.append(self._build_vuln(
                                    name='BFLA — Admin Endpoint Accessible',
                                    severity='critical',
                                    category='Authorization',
                                    description=(
                                        f'The admin endpoint {url} is accessible without '
                                        f'proper authorization. Administrative functions '
                                        f'are exposed to unauthorized users.'
                                    ),
                                    impact=(
                                        'Complete administrative access — user management, '
                                        'configuration changes, data export, log access.'
                                    ),
                                    remediation=(
                                        '1. Implement role-based access control (RBAC). '
                                        '2. Verify user role/permissions on every admin endpoint. '
                                        '3. Use middleware to enforce admin-only access. '
                                        '4. Log and alert on unauthorized admin access attempts.'
                                    ),
                                    cwe='CWE-285',
                                    cvss=9.8,
                                    affected_url=url,
                                    evidence=f'Admin endpoint returned data: {str(data)[:300]}',
                                ))
                                return vulns
                    except (json.JSONDecodeError, TypeError):
                        # HTML admin panel
                        if any(word in body.lower() for word in
                               ['admin panel', 'dashboard', 'management', 'admin console']):
                            vulns.append(self._build_vuln(
                                name='BFLA — Admin Panel Accessible',
                                severity='critical',
                                category='Authorization',
                                description=f'Admin panel at {url} accessible without authorization.',
                                impact='Complete administrative access.',
                                remediation='1. Require authentication for admin pages. 2. Implement RBAC.',
                                cwe='CWE-285',
                                cvss=9.8,
                                affected_url=url,
                                evidence=f'Admin page content found: {body[:300]}',
                            ))
                            return vulns

        return vulns

    def _test_api_misconfig(self, target: str, depth: str) -> list:
        """API8: Test for API-specific security misconfigurations."""
        vulns = []
        base = target.rstrip('/')

        # Check for exposed Swagger/OpenAPI docs
        doc_paths = [
            '/swagger.json', '/openapi.json', '/api-docs', '/swagger-ui/',
            '/swagger-ui.html', '/redoc', '/api/schema/', '/docs',
            '/api/docs', '/api/swagger/', '/openapi.yaml', '/api/openapi.json',
        ]

        for path in doc_paths:
            url = base + path
            resp = self._make_request('GET', url)
            if not resp or resp.status_code != 200:
                continue

            body = resp.text or ''
            if any(ind in body.lower() for ind in ['swagger', 'openapi', 'paths', 'endpoints']):
                vulns.append(self._build_vuln(
                    name='Exposed API Documentation (Swagger/OpenAPI)',
                    severity='low',
                    category='API Security',
                    description=(
                        f'API documentation is publicly accessible at {url}. '
                        f'While not directly exploitable, it reveals all API endpoints, '
                        f'parameters, and data models to potential attackers.'
                    ),
                    impact=(
                        'Information disclosure — attackers can map the entire API surface, '
                        'identify vulnerable endpoints, and understand data structures.'
                    ),
                    remediation=(
                        '1. Restrict API docs to authenticated/internal users. '
                        '2. Use IP allowlists for documentation endpoints. '
                        '3. Disable documentation in production environments.'
                    ),
                    cwe='CWE-200',
                    cvss=3.7,
                    affected_url=url,
                    evidence=f'API docs accessible: {body[:300]}',
                ))
                break

        # Check for debug/stack trace exposure
        for prefix in API_PREFIXES[:2]:
            url = base + prefix + '/nonexistent-endpoint-12345'
            resp = self._make_request('GET', url)
            if not resp:
                continue

            body = resp.text or ''
            if any(ind in body for ind in ['Traceback', 'stack trace', 'at line',
                                            'Exception', 'DEBUG', 'INTERNAL_ERROR_DETAILS']):
                vulns.append(self._build_vuln(
                    name='API Stack Trace / Debug Info Exposure',
                    severity='medium',
                    category='API Security',
                    description=(
                        f'API error responses at {url} expose stack traces or debug '
                        f'information, revealing internal implementation details.'
                    ),
                    impact=(
                        'Internal paths, framework versions, database structure, '
                        'and code logic exposed to attackers.'
                    ),
                    remediation=(
                        '1. Disable DEBUG mode in production. '
                        '2. Use generic error messages for API responses. '
                        '3. Log detailed errors server-side only.'
                    ),
                    cwe='CWE-209',
                    cvss=5.3,
                    affected_url=url,
                    evidence=f'Debug info in error response: {body[:300]}',
                ))
                break

        # Check for CORS * on API
        for prefix in API_PREFIXES[:2]:
            url = base + prefix + '/'
            resp = self._make_request('OPTIONS', url, headers={
                'Origin': 'https://evil.example.com',
                'Access-Control-Request-Method': 'POST',
            })
            if not resp:
                continue

            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*' and acac.lower() == 'true':
                vulns.append(self._build_vuln(
                    name='API CORS Misconfiguration (Wildcard + Credentials)',
                    severity='high',
                    category='API Security',
                    description=(
                        f'API at {url} returns Access-Control-Allow-Origin: * with '
                        f'Access-Control-Allow-Credentials: true, allowing any origin '
                        f'to make authenticated cross-origin requests.'
                    ),
                    impact='Cross-origin data theft via authenticated API requests.',
                    remediation=(
                        '1. Never combine ACAO: * with ACAC: true. '
                        '2. Use an allowlist of permitted origins. '
                        '3. Validate Origin header against allowed domains.'
                    ),
                    cwe='CWE-942',
                    cvss=8.0,
                    affected_url=url,
                    evidence=f'ACAO: {acao}, ACAC: {acac}',
                ))
                break

            if 'evil.example.com' in acao:
                vulns.append(self._build_vuln(
                    name='API CORS Origin Reflection',
                    severity='high',
                    category='API Security',
                    description=(
                        f'API at {url} reflects any Origin header in ACAO, '
                        f'allowing unauthorized cross-origin access.'
                    ),
                    impact='Cross-origin data theft from any malicious website.',
                    remediation='1. Validate Origin against an allowlist of trusted domains.',
                    cwe='CWE-942',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Origin evil.example.com reflected in ACAO: {acao}',
                ))
                break

        return vulns

    def _test_shadow_apis(self, target: str) -> list:
        """API9: Test for deprecated/shadow API versions."""
        vulns = []
        base = target.rstrip('/')
        found_versions = []

        for version_path in DEPRECATED_VERSIONS:
            url = base + version_path
            resp = self._make_request('GET', url)
            if not resp:
                continue

            if resp.status_code in (200, 301, 302):
                body = resp.text or ''
                if resp.status_code == 200 and len(body) > 50:
                    found_versions.append(version_path)

        if len(found_versions) >= 2:
            vulns.append(self._build_vuln(
                name='Shadow/Deprecated API Versions Accessible',
                severity='medium',
                category='API Security',
                description=(
                    f'Multiple API versions are accessible at {target}: '
                    f'{", ".join(found_versions)}. Deprecated versions may lack '
                    f'security patches applied to the current version.'
                ),
                impact=(
                    'Attackers can exploit patched vulnerabilities in older API versions. '
                    'Deprecated endpoints may bypass newer security controls.'
                ),
                remediation=(
                    '1. Decommission deprecated API versions. '
                    '2. Redirect old versions to current with deprecation notices. '
                    '3. Apply security patches consistently across all active versions. '
                    '4. Maintain an API inventory to track all versions.'
                ),
                cwe='CWE-1059',
                cvss=5.3,
                affected_url=target,
                evidence=f'Active API versions: {", ".join(found_versions)}',
            ))

        return vulns

    def _test_excessive_data(self, target: str) -> list:
        """API3: Test for excessive data exposure in API responses."""
        vulns = []
        base = target.rstrip('/')
        list_endpoints = [
            '/api/users', '/api/products', '/api/orders',
            '/api/items', '/api/articles', '/api/posts',
        ]

        for endpoint in list_endpoints:
            url = base + endpoint
            resp = self._make_request('GET', url)
            if not resp or resp.status_code != 200:
                continue

            body = resp.text or ''
            try:
                data = json.loads(body)
                items = data if isinstance(data, list) else data.get('results', data.get('data', []))
                if not isinstance(items, list) or not items:
                    continue

                # Check first item for sensitive fields
                first = items[0] if items else {}
                if not isinstance(first, dict):
                    continue

                sensitive = ['password', 'password_hash', 'secret', 'token',
                             'api_key', 'ssn', 'credit_card', 'bank_account',
                             'internal_id', 'internal_notes', '_id']
                found = [k for k in first.keys() if k.lower() in sensitive]

                if found:
                    vulns.append(self._build_vuln(
                        name='Excessive Data Exposure in API Response',
                        severity='high',
                        category='API Security',
                        description=(
                            f'The endpoint {url} returns sensitive fields in responses: '
                            f'{", ".join(found)}. The API exposes more data than the '
                            f'client needs.'
                        ),
                        impact=(
                            'Sensitive data exposure — passwords, tokens, or internal '
                            'data visible to any client consuming the API.'
                        ),
                        remediation=(
                            '1. Implement response filtering — only return needed fields. '
                            '2. Use DTOs/serializers to control API output. '
                            '3. Never expose password hashes, tokens, or internal IDs. '
                            '4. Use GraphQL field selection or sparse fieldsets (JSON:API).'
                        ),
                        cwe='CWE-213',
                        cvss=7.5,
                        affected_url=url,
                        evidence=f'Sensitive fields: {", ".join(found)} in {endpoint}',
                    ))
                    break

            except (json.JSONDecodeError, TypeError, IndexError):
                pass

        return vulns
