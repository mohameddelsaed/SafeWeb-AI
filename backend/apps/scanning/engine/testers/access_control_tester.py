"""
AccessControlTester — Professional-grade broken access control detection.
OWASP A01:2021 — Broken Access Control.

Tests for: IDOR, path traversal (40+ payloads), forced browsing (200+ paths),
HTTP method override, privilege escalation, and missing authorization.
"""
import re
import logging
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester
from apps.scanning.engine.payloads.traversal_payloads import (
    get_traversal_payloads_by_depth,
    FILE_PARAM_NAMES,
    TRAVERSAL_SUCCESS_PATTERNS,
)
from apps.scanning.engine.payloads.sensitive_paths import (
    get_sensitive_paths_by_depth,
)

logger = logging.getLogger(__name__)


class AccessControlTester(BaseTester):
    """Test for broken access control vulnerabilities."""

    TESTER_NAME = 'Access Control'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Test IDOR in URL parameters
        vulns = self._test_idor(page)
        vulnerabilities.extend(vulns)

        # Test directory traversal
        traversal_payloads = get_traversal_payloads_by_depth(depth)
        traversal_payloads = self._augment_payloads_with_seclists(traversal_payloads, 'lfi', recon_data)
        vulns = self._test_directory_traversal(page, traversal_payloads)
        vulnerabilities.extend(vulns)

        # Test forced browsing / sensitive path exposure
        if depth in ('medium', 'deep'):
            paths = get_sensitive_paths_by_depth(depth)
            vulns = self._test_forced_browsing(page.url, paths)
            vulnerabilities.extend(vulns)

        # Check for missing function-level access control
        vuln = self._test_method_override(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Privilege escalation via parameter tampering (medium/deep)
        if depth in ('medium', 'deep'):
            vulns = self._test_privilege_escalation(page)
            vulnerabilities.extend(vulns)

        # HTTP verb tampering (deep)
        if depth == 'deep':
            vuln = self._test_verb_tampering(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_idor(self, page):
        """Test for Insecure Direct Object References.

        With dual sessions: victim fetches → attacker fetches same resource.
        """
        vulnerabilities = []

        # ── Cross-account IDOR (dual session) ────────────────────────────
        if self.has_victim_session:
            for param_name, param_value in page.parameters.items():
                if not self._is_id_param(param_name, param_value):
                    continue
                victim_resp = self._make_victim_request('GET', page.url)
                if not victim_resp or victim_resp.status_code != 200:
                    continue
                if len(victim_resp.text or '') < 100:
                    continue

                attacker_resp = self._make_request('GET', page.url)
                if not attacker_resp or attacker_resp.status_code != 200:
                    continue
                if len(attacker_resp.text or '') < 100:
                    continue

                v_len = len(victim_resp.text)
                a_len = len(attacker_resp.text)
                if abs(v_len - a_len) < max(v_len * 0.3, 100):
                    vulnerabilities.append(self._build_vuln(
                        name=f'Confirmed IDOR: {param_name}',
                        severity='critical',
                        category='Broken Access Control',
                        description=f'Cross-account test: attacker accessed victim\'s data via '
                                   f'"{param_name}={param_value}". No authorization check.',
                        impact='Attackers can access other users\' data by manipulating object references.',
                        remediation='Implement proper authorization checks for every data access.',
                        cwe='CWE-639',
                        cvss=9.1,
                        affected_url=page.url,
                        evidence=f'Parameter: {param_name}={param_value}\n'
                                f'Victim: {v_len} bytes | Attacker: {a_len} bytes\n'
                                f'Cross-account IDOR confirmed.',
                    ))
                    break
            return vulnerabilities

        # ── Single-session fallback ──────────────────────────────────────

        for param_name, param_value in page.parameters.items():
            if not self._is_id_param(param_name, param_value):
                continue

            test_ids = self._generate_test_ids(param_value)
            for test_id in test_ids:
                parsed = urlparse(page.url)
                params = parse_qs(parsed.query)
                params[param_name] = test_id

                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), ''
                ))

                response = self._make_request('GET', test_url)
                if response and response.status_code == 200:
                    original = self._make_request('GET', page.url)
                    if original and response.text != original.text and len(response.text) > 100:
                        vulnerabilities.append(self._build_vuln(
                            name=f'Potential IDOR: {param_name}',
                            severity='high',
                            category='Broken Access Control',
                            description=f'Parameter "{param_name}" may be vulnerable to Insecure Direct Object '
                                       f'Reference — different IDs return different content without authorization checks.',
                            impact='Attackers can access other users\' data by manipulating object references.',
                            remediation='Implement proper authorization checks for every data access. '
                                       'Use indirect object references or UUIDs instead of sequential IDs.',
                            cwe='CWE-639',
                            cvss=6.5,
                            affected_url=page.url,
                            evidence=f'Parameter: {param_name}\nOriginal: {param_value}\nTest: {test_id}\n'
                                    f'Both returned 200 with different content.',
                        ))
                        break

        return vulnerabilities

    def _test_directory_traversal(self, page, payloads):
        """Test for path traversal vulnerabilities with 40+ payloads."""
        vulnerabilities = []

        for param_name, param_value in page.parameters.items():
            if not any(k in param_name.lower() for k in FILE_PARAM_NAMES):
                continue

            for payload in payloads:
                parsed = urlparse(page.url)
                params = parse_qs(parsed.query)
                params[param_name] = payload

                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), ''
                ))

                response = self._make_request('GET', test_url)
                if response and response.status_code == 200:
                    for pattern in TRAVERSAL_SUCCESS_PATTERNS:
                        if re.search(pattern, response.text):
                            vulnerabilities.append(self._build_vuln(
                                name=f'Path Traversal: {param_name}',
                                severity='critical',
                                category='Broken Access Control',
                                description=f'Parameter "{param_name}" is vulnerable to directory traversal, '
                                           f'allowing access to files outside the web root.',
                                impact='Attackers can read arbitrary files on the server, including '
                                      'configuration files, password files, and application source code.',
                                remediation='Validate and sanitize file paths. Use a whitelist of allowed files. '
                                           'Canonicalize paths and verify they resolve within the intended directory.',
                                cwe='CWE-22',
                                cvss=9.1,
                                affected_url=page.url,
                                evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                                        f'System file content detected in response.',
                            ))
                            return vulnerabilities

        return vulnerabilities

    def _test_forced_browsing(self, url, paths):
        """Test for access to restricted resources using 200+ sensitive paths."""
        parsed = urlparse(url)
        base = f'{parsed.scheme}://{parsed.netloc}'
        vulnerabilities = []
        found_count = 0

        for path in paths:
            if found_count >= 5:
                break

            test_url = urljoin(base, path)
            response = self._make_request('GET', test_url)
            if not response:
                continue

            if response.status_code == 200 and len(response.text) > 200:
                body = response.text.lower()

                # Check for admin/sensitive content indicators
                admin_indicators = [
                    'dashboard', 'admin', 'users', 'settings',
                    'configuration', 'manage', 'control panel',
                    'phpinfo', 'debug', 'profiler', 'swagger',
                    'api-docs', 'graphql', 'graphiql',
                ]

                # Check for config/secret indicators
                config_indicators = [
                    'database', 'password', 'secret', 'api_key',
                    'access_key', 'private_key', 'credentials',
                    '[core]', 'db_host', 'db_pass',
                ]

                # Check for source code / VCS
                vcs_indicators = [
                    'ref:', 'commit', '[remote', '[branch',  # .git
                    '<?php', '<?xml', 'import ', 'from ',     # source
                ]

                severity = 'medium'
                category_detail = 'administrative'

                if any(ind in body for ind in config_indicators):
                    severity = 'critical'
                    category_detail = 'configuration/secrets'
                elif any(ind in body for ind in vcs_indicators):
                    severity = 'high'
                    category_detail = 'source code/VCS'
                elif any(ind in body for ind in admin_indicators):
                    severity = 'high'
                    category_detail = 'administrative'
                else:
                    continue  # Not interesting enough

                found_count += 1
                vulnerabilities.append(self._build_vuln(
                    name=f'Sensitive Path Exposed: {path}',
                    severity=severity,
                    category='Broken Access Control',
                    description=f'The {category_detail} path {path} is accessible without proper authorization.',
                    impact='Unauthorized users can access sensitive data, configuration files, '
                          'or administrative functions.',
                    remediation='Block access to sensitive paths via web server configuration. '
                               'Implement authentication and authorization for all endpoints. '
                               'Remove debug/development endpoints from production.',
                    cwe='CWE-425',
                    cvss=9.1 if severity == 'critical' else 7.5,
                    affected_url=test_url,
                    evidence=f'HTTP 200 for {path} — {category_detail} content detected.',
                ))

        return vulnerabilities

    def _test_method_override(self, url):
        """Test for HTTP method override bypasses."""
        headers = {'X-HTTP-Method-Override': 'DELETE'}
        response = self._make_request('POST', url, headers=headers)
        if response and response.status_code in (200, 204):
            headers2 = {'X-HTTP-Method-Override': 'PUT'}
            response2 = self._make_request('POST', url, headers=headers2)
            if response2 and response2.status_code in (200, 204):
                return self._build_vuln(
                    name='HTTP Method Override Accepted',
                    severity='medium',
                    category='Broken Access Control',
                    description='The server processes X-HTTP-Method-Override headers, '
                               'potentially bypassing method-based access controls.',
                    impact='Attackers may use method override to access restricted operations.',
                    remediation='Disable HTTP method override in production. '
                               'Apply access controls based on the actual HTTP method.',
                    cwe='CWE-650',
                    cvss=5.3,
                    affected_url=url,
                    evidence='Server accepted X-HTTP-Method-Override header.',
                )
        return None

    def _test_privilege_escalation(self, page):
        """Test for privilege escalation via parameter tampering and cross-role access.

        With dual sessions: victim accesses admin-like pages → checks if attacker
        can also access them, confirming vertical privilege escalation.
        """
        vulnerabilities = []

        # ── Cross-role vertical privilege escalation (dual session) ──────
        if self.has_victim_session:
            # If attacker is low-priv and can access the same pages as victim (high-priv),
            # that's a confirmed privilege escalation
            attacker_resp = self._make_request('GET', page.url)
            victim_resp = self._make_victim_request('GET', page.url)
            if (attacker_resp and victim_resp and
                    attacker_resp.status_code == 200 and victim_resp.status_code == 200):
                body = attacker_resp.text.lower()
                if any(k in body for k in ('admin', 'dashboard', 'manage', 'settings', 'users')):
                    # Both roles see admin content — check if they're different roles
                    vulnerabilities.append(self._build_vuln(
                        name='Cross-Role Privilege Escalation',
                        severity='critical',
                        category='Broken Access Control',
                        description=f'Both attacker and victim sessions can access admin-level '
                                   f'content at {page.url}. Missing role-based authorization.',
                        impact='Low-privilege users can access admin functionality.',
                        remediation='Implement role-based access control (RBAC). Verify user '
                                   'role server-side before serving admin resources.',
                        cwe='CWE-269',
                        cvss=9.1,
                        affected_url=page.url,
                        evidence=f'Attacker: HTTP {attacker_resp.status_code} ({len(attacker_resp.text)} bytes)\n'
                                f'Victim: HTTP {victim_resp.status_code} ({len(victim_resp.text)} bytes)\n'
                                f'Admin content accessible to both roles.',
                    ))

        # ── Parameter tampering fallback ─────────────────────────────────
        priv_params = ['role', 'admin', 'is_admin', 'user_type', 'level',
                       'privilege', 'permission', 'group', 'access_level']

        for param_name, param_value in page.parameters.items():
            if param_name.lower() not in priv_params:
                continue

            escalation_values = ['admin', 'administrator', 'root', '1', 'true', 'superuser']
            for value in escalation_values:
                if value == param_value:
                    continue

                parsed = urlparse(page.url)
                params = parse_qs(parsed.query)
                params[param_name] = value
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), ''
                ))

                response = self._make_request('GET', test_url)
                if response and response.status_code == 200:
                    body = response.text.lower()
                    if any(k in body for k in ('admin', 'dashboard', 'manage', 'settings')):
                        vulnerabilities.append(self._build_vuln(
                            name=f'Privilege Escalation: {param_name}',
                            severity='critical',
                            category='Broken Access Control',
                            description=f'The parameter "{param_name}" can be tampered to escalate privileges. '
                                       f'Setting it to "{value}" returned admin-level content.',
                            impact='Attackers can gain admin privileges by modifying URL parameters.',
                            remediation='Validate authorization server-side. Never trust client-supplied '
                                       'role/privilege parameters.',
                            cwe='CWE-269',
                            cvss=8.8,
                            affected_url=page.url,
                            evidence=f'Parameter: {param_name}={value} returned admin content.',
                        ))
                        break

        return vulnerabilities

    def _test_verb_tampering(self, url):
        """Test for HTTP verb tampering to bypass access controls."""
        verbs = ['HEAD', 'OPTIONS', 'TRACE', 'PATCH']
        for verb in verbs:
            response = self._make_request(verb, url)
            if not response:
                continue

            if verb == 'TRACE' and response.status_code == 200:
                if 'TRACE' in response.text:
                    return self._build_vuln(
                        name='HTTP TRACE Method Enabled',
                        severity='medium',
                        category='Broken Access Control',
                        description='The server responds to HTTP TRACE requests, which can '
                                   'be used for Cross-Site Tracing (XST) attacks.',
                        impact='Attackers can use TRACE to steal HTTP-only cookies and '
                              'authentication tokens via XSS.',
                        remediation='Disable the TRACE HTTP method on the web server.',
                        cwe='CWE-693',
                        cvss=5.3,
                        affected_url=url,
                        evidence='HTTP TRACE method returned 200 with request echo.',
                    )
        return None

    def _is_id_param(self, name, value):
        """Check if a parameter looks like an object ID."""
        if any(k in name.lower() for k in ('id', 'uid', 'user', 'account', 'order', 'doc')):
            return True
        try:
            int(value)
            return True
        except (ValueError, TypeError):
            pass
        return False

    def _generate_test_ids(self, original_value):
        """Generate test IDs based on the original value."""
        test_ids = []
        try:
            num = int(original_value)
            test_ids.extend([str(num + 1), str(num - 1), '1', '0'])
        except (ValueError, TypeError):
            test_ids.extend(['1', '2', 'admin'])
        return test_ids[:2]
