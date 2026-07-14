"""
NoSQLInjectionTester — NoSQL Injection detection.
OWASP A03:2021 — Injection.

Tests for: MongoDB operator injection ($gt, $ne, $regex, $where),
JSON body injection, URL parameter injection, JavaScript injection,
and authentication bypass via NoSQL injection.
"""
import re
import json
import logging
from .base_tester import BaseTester
from ..payloads.nosql_payloads import (
    URL_PARAM_INJECTION as NOSQL_URL_PAYLOADS,
    JSON_INJECTION as NOSQL_JSON_PAYLOADS,
    NOSQL_ERROR_PATTERNS,
)

logger = logging.getLogger(__name__)

# Parameters likely to be injectable
AUTH_PARAM_NAMES = {'username', 'user', 'email', 'login', 'password', 'passwd', 'pass', 'pwd'}
SEARCH_PARAM_NAMES = {'q', 'query', 'search', 'filter', 'find', 'id', 'name', 'key'}


class NoSQLInjectionTester(BaseTester):
    """Test for NoSQL injection vulnerabilities."""

    TESTER_NAME = 'NoSQL Injection'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # 1. Test URL parameters
        vulns = self._test_url_params(page)
        vulnerabilities.extend(vulns)

        # 2. Test forms
        vulns = self._test_form_injection(page, depth)
        vulnerabilities.extend(vulns)

        # 3. Test JSON body injection on API-like endpoints
        if depth in ('medium', 'deep'):
            vulns = self._test_json_injection(page)
            vulnerabilities.extend(vulns)

        # 4. Test auth bypass (deep only)
        if depth == 'deep':
            vulns = self._test_auth_bypass(page)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _test_url_params(self, page) -> list:
        """Test URL parameters for NoSQL operator injection."""
        vulnerabilities = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(page.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return vulnerabilities

        for param_name in params:
            # Test MongoDB operators
            for operator_payload in NOSQL_URL_PAYLOADS[:6]:
                modified_params = dict(params)
                modified_params[f'{param_name}[$ne]'] = ['']
                modified_params.pop(param_name, None)

                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    response = self._make_request('GET', test_url)
                except Exception:
                    continue

                if response and self._has_nosql_error(response.text):
                    vulnerabilities.append(self._build_vuln(
                        name='NoSQL Injection via URL Parameter',
                        severity='critical',
                        category='NoSQL Injection',
                        description=f'The parameter "{param_name}" is vulnerable to NoSQL operator '
                                   f'injection. MongoDB query operators were reflected in error output.',
                        impact='Attackers can bypass authentication, extract data, or modify queries '
                              'by injecting NoSQL operators.',
                        remediation='Sanitize user input. Use parameterized queries. '
                                   'Validate input types strictly. Reject inputs starting with "$".',
                        cwe='CWE-943',
                        cvss=9.8,
                        affected_url=test_url,
                        evidence=f'Parameter: {param_name}\nPayload: {param_name}[$ne]=\n'
                                f'Error patterns detected in response.',
                    ))
                    break

            # Test string payloads
            for payload in NOSQL_URL_PAYLOADS[:5]:
                modified_params = dict(params)
                modified_params[param_name] = [payload]

                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    response = self._make_request('GET', test_url)
                except Exception:
                    continue

                if response and self._has_nosql_error(response.text):
                    vulnerabilities.append(self._build_vuln(
                        name='NoSQL Injection via URL Parameter',
                        severity='critical',
                        category='NoSQL Injection',
                        description=f'The parameter "{param_name}" is vulnerable to NoSQL injection.',
                        impact='Attackers can manipulate database queries to bypass authentication, '
                              'extract information, or cause denial of service.',
                        remediation='Sanitize all user input. Use parameterized queries. '
                                   'Validate input types. Use allowlists for expected values.',
                        cwe='CWE-943',
                        cvss=9.8,
                        affected_url=test_url,
                        evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                                f'NoSQL error detected.',
                    ))
                    break

        return vulnerabilities

    def _test_form_injection(self, page, depth: str) -> list:
        """Test form fields for NoSQL injection."""
        vulnerabilities = []

        for form in page.forms:
            target_url = form.action or page.url

            for inp in form.inputs:
                if not inp.name or inp.input_type in ('submit', 'button', 'hidden', 'file'):
                    continue

                payloads = NOSQL_URL_PAYLOADS[:3] if depth == 'shallow' else NOSQL_URL_PAYLOADS[:8]
                for payload in payloads:
                    data = {}
                    for fi in form.inputs:
                        if fi.name:
                            if fi.name == inp.name:
                                data[fi.name] = payload
                            else:
                                data[fi.name] = fi.value or 'test'

                    try:
                        method = form.method.upper() if form.method else 'POST'
                        response = self._make_request(method, target_url, data=data)
                    except Exception:
                        continue

                    if response and self._has_nosql_error(response.text):
                        vulnerabilities.append(self._build_vuln(
                            name='NoSQL Injection via Form',
                            severity='critical',
                            category='NoSQL Injection',
                            description=f'Form field "{inp.name}" at {target_url} is vulnerable to '
                                       f'NoSQL injection.',
                            impact='Attackers can manipulate NoSQL queries to bypass authentication, '
                                  'extract data, or cause application errors.',
                            remediation='Sanitize and validate all user input. Use parameterized queries. '
                                       'Reject special characters like $, {, }, and operators.',
                            cwe='CWE-943',
                            cvss=9.8,
                            affected_url=target_url,
                            evidence=f'Field: {inp.name}\nPayload: {payload}\n'
                                    f'NoSQL error detected in response.',
                        ))
                        break

                if vulnerabilities:
                    break  # One finding per form is sufficient

        return vulnerabilities

    def _test_json_injection(self, page) -> list:
        """Test JSON body injection on API-like endpoints."""
        vulnerabilities = []
        from urllib.parse import urlparse

        parsed = urlparse(page.url)
        path = parsed.path.lower()

        # Check if this looks like an API endpoint
        api_indicators = ('/api/', '/graphql', '/rest/', '/v1/', '/v2/')
        if not any(ind in path for ind in api_indicators):
            return vulnerabilities

        for payload_obj in NOSQL_JSON_PAYLOADS[:5]:
            try:
                json_body = json.loads(payload_obj) if isinstance(payload_obj, str) else payload_obj
            except (json.JSONDecodeError, TypeError):
                json_body = {"username": payload_obj, "password": payload_obj}

            try:
                response = self._make_request(
                    'POST', page.url,
                    json=json_body,
                    headers={'Content-Type': 'application/json'},
                )
            except Exception:
                continue

            if response and self._has_nosql_error(response.text):
                vulnerabilities.append(self._build_vuln(
                    name='NoSQL Injection via JSON Body',
                    severity='critical',
                    category='NoSQL Injection',
                    description='The API endpoint accepts JSON payloads that can manipulate '
                               'NoSQL queries.',
                    impact='Attackers can inject NoSQL operators via JSON request bodies to '
                          'bypass authentication or extract data.',
                    remediation='Validate JSON schema strictly. Reject unexpected operators. '
                               'Use ORM/ODM with parameterized queries.',
                    cwe='CWE-943',
                    cvss=9.8,
                    affected_url=page.url,
                    evidence=f'Payload: {json.dumps(json_body)[:200]}\n'
                            f'NoSQL error detected.',
                ))
                break

        return vulnerabilities

    def _test_auth_bypass(self, page) -> list:
        """Test authentication bypass via NoSQL injection."""
        vulnerabilities = []

        for form in page.forms:
            # Look for login/auth forms
            form_html = str(form).lower()
            is_auth = any(k in form_html for k in ('login', 'signin', 'auth', 'password'))
            if not is_auth:
                continue

            target_url = form.action or page.url

            # Build base data
            username_field = None
            password_field = None
            data = {}

            for fi in form.inputs:
                if not fi.name:
                    continue
                name_lower = fi.name.lower()
                if any(k in name_lower for k in ('user', 'email', 'login')):
                    username_field = fi.name
                elif any(k in name_lower for k in ('pass', 'pwd')):
                    password_field = fi.name
                else:
                    data[fi.name] = fi.value or ''

            if not (username_field and password_field):
                continue

            # Test NoSQL auth bypass payloads
            bypass_payloads = [
                # Operator injection
                {username_field: '{"$gt":""}', password_field: '{"$gt":""}'},
                {username_field: '{"$ne":"invalid"}', password_field: '{"$ne":"invalid"}'},
                {username_field: '{"$regex":".*"}', password_field: '{"$regex":".*"}'},
            ]

            for payload_data in bypass_payloads:
                full_data = {**data, **payload_data}

                try:
                    response = self._make_request('POST', target_url, data=full_data)
                except Exception:
                    continue

                if response:
                    # Check for successful auth bypass
                    body_lower = response.text.lower()
                    bypass_indicators = ['dashboard', 'welcome', 'logout', 'profile',
                                        'successfully', 'authenticated']
                    if any(k in body_lower for k in bypass_indicators):
                        vulnerabilities.append(self._build_vuln(
                            name='Authentication Bypass via NoSQL Injection',
                            severity='critical',
                            category='NoSQL Injection',
                            description='The login form is vulnerable to NoSQL injection. '
                                       'Authentication can be bypassed using NoSQL operators.',
                            impact='Complete authentication bypass. Attackers can log in as any user '
                                  'without knowing the password.',
                            remediation='Validate input types strictly (reject objects/arrays). '
                                       'Use parameterized queries. Implement rate limiting.',
                            cwe='CWE-943',
                            cvss=9.8,
                            affected_url=target_url,
                            evidence=f'Bypass payload: {json.dumps(payload_data)[:200]}\n'
                                    f'Authentication bypass indicators detected.',
                        ))
                        return vulnerabilities

        return vulnerabilities

    def _has_nosql_error(self, body: str) -> bool:
        """Check response for NoSQL-related errors."""
        if not body:
            return False
        body_lower = body.lower()
        return any(re.search(pattern, body_lower) for pattern in NOSQL_ERROR_PATTERNS)
