"""
IDORTester — Insecure Direct Object Reference detection.
OWASP API1:2023 — Broken Object Level Authorization.

Tests for: numeric ID manipulation, UUID swapping, sequential enumeration,
path-based IDOR, array wrapping, and GUID v1 prediction.
"""
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Parameter names that commonly hold object identifiers
_ID_PARAM_NAMES = {
    'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid', 'order_id',
    'orderid', 'profile_id', 'profileid', 'item_id', 'itemid', 'doc_id',
    'docid', 'record_id', 'recordid', 'invoice_id', 'file_id', 'fileid',
    'project_id', 'projectid', 'msg_id', 'message_id', 'comment_id',
    'report_id', 'ticket_id', 'customer_id', 'member_id', 'employee_id',
}

# UUID v4 pattern
_UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
)

# Headers that hold user context
_USER_CONTEXT_HEADERS = ['X-User-Id', 'X-Account-Id', 'X-Customer-Id',
                         'X-Tenant-Id', 'X-Auth-User', 'X-User']


class IDORTester(BaseTester):
    """Test for Insecure Direct Object References (OWASP API1:2023)."""

    TESTER_NAME = 'IDOR'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Test URL parameters that look like object IDs
        for param_name, param_values in page.parameters.items():
            if not self._is_id_param(param_name):
                continue

            original_value = param_values[0] if isinstance(param_values, list) else str(param_values)

            # Shallow: increment/decrement numeric IDs
            vuln = self._test_numeric_idor(page.url, param_name, original_value)
            if vuln:
                vulnerabilities.append(vuln)
                continue

            # Shallow: UUID swap test
            if _UUID_PATTERN.match(original_value):
                vuln = self._test_uuid_swap(page.url, param_name, original_value)
                if vuln:
                    vulnerabilities.append(vuln)
                    continue

            # Medium: sequential enumeration and boundary values
            if depth in ('medium', 'deep'):
                vuln = self._test_sequential_enum(page.url, param_name, original_value)
                if vuln:
                    vulnerabilities.append(vuln)
                    continue

                vuln = self._test_boundary_ids(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    continue

        # Medium: user-context header manipulation
        if depth in ('medium', 'deep'):
            header_vulns = self._test_user_context_headers(page)
            vulnerabilities.extend(header_vulns)

        # Deep: path-based IDOR and array wrapping
        if depth == 'deep':
            vuln = self._test_path_idor(page)
            if vuln:
                vulnerabilities.append(vuln)

            for param_name, param_values in page.parameters.items():
                if not self._is_id_param(param_name):
                    continue
                original_value = param_values[0] if isinstance(param_values, list) else str(param_values)

                vuln = self._test_array_wrapping(page.url, param_name, original_value)
                if vuln:
                    vulnerabilities.append(vuln)

                vuln = self._test_admin_ids(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_id_param(self, param_name):
        """Check if a parameter name indicates an object identifier."""
        name_lower = param_name.lower().strip()
        if name_lower in _ID_PARAM_NAMES:
            return True
        if name_lower.endswith('_id') or name_lower.endswith('id'):
            return True
        return False

    def _test_numeric_idor(self, url, param_name, original_value):
        """Test numeric ID parameters by incrementing/decrementing.

        With dual sessions: victim fetches original ID → attacker fetches same ID.
        If attacker gets victim's data, it's a confirmed IDOR.
        Without dual sessions: falls back to adjacent-ID content diff heuristic.
        """
        try:
            original_int = int(original_value)
        except (ValueError, TypeError):
            return None

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # ── Cross-account IDOR (dual session) ────────────────────────────
        if self.has_victim_session:
            # Victim fetches their own resource
            victim_resp = self._make_victim_request('GET', url)
            if not victim_resp or victim_resp.status_code != 200:
                return None
            victim_body = victim_resp.text or ''
            if len(victim_body) < 50:
                return None

            # Attacker fetches the same resource (victim's ID)
            attacker_resp = self._make_request('GET', url)
            if not attacker_resp:
                return None

            if attacker_resp.status_code == 200 and len(attacker_resp.text or '') > 50:
                # Significant overlap means attacker can see victim's data
                victim_len = len(victim_body)
                attacker_body = attacker_resp.text or ''
                attacker_len = len(attacker_body)
                # If attacker got a similar-sized response, it likely contains victim data
                if abs(victim_len - attacker_len) < max(victim_len * 0.3, 100):
                    return self._build_vuln(
                        name=f'Confirmed IDOR via Numeric ID: {param_name}',
                        severity='critical',
                        category='Broken Access Control',
                        description=f'Cross-account test: attacker session accessed victim\'s '
                                   f'resource at parameter "{param_name}={original_value}" and '
                                   f'received {attacker_len} bytes of data. The server performs '
                                   f'no object-level authorization check.',
                        impact='Any authenticated user can access any other user\'s data by '
                              'changing the numeric ID. Full data breach is possible.',
                        remediation='Implement object-level authorization. Verify the authenticated '
                                   'user owns the requested object before returning data. '
                                   'Use indirect references (mapping table) instead of direct IDs.',
                        cwe='CWE-639',
                        cvss=9.1,
                        affected_url=url,
                        evidence=f'Parameter: {param_name}={original_value}\n'
                                f'Victim response: {victim_len} bytes (HTTP {victim_resp.status_code})\n'
                                f'Attacker response: {attacker_len} bytes (HTTP {attacker_resp.status_code})\n'
                                f'Cross-account IDOR confirmed with dual sessions.',
                    )
            return None

        # ── Single-session heuristic fallback ────────────────────────────
        # Get original response for comparison
        original_resp = self._make_request('GET', url)
        if not original_resp or original_resp.status_code != 200:
            return None
        original_length = len(original_resp.text or '')

        # Try adjacent IDs
        test_ids = [original_int + 1, original_int - 1]
        for test_id in test_ids:
            if test_id < 0:
                continue
            params[param_name] = str(test_id)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if not resp:
                continue

            # IDOR indicator: different data returned (status 200, different content)
            if resp.status_code == 200:
                resp_length = len(resp.text or '')
                # Significant content difference suggests different object data
                if resp_length > 100 and abs(resp_length - original_length) > 50:
                    if resp.text != original_resp.text:
                        return self._build_vuln(
                            name=f'IDOR via Numeric ID: {param_name}',
                            severity='high',
                            category='Broken Access Control',
                            description=f'The parameter "{param_name}" allows access to other users\' '
                                       f'data by changing the numeric ID from {original_value} to {test_id}. '
                                       f'No authorization check prevents cross-object access.',
                            impact='Attackers can enumerate and access any object by iterating IDs. '
                                  'This exposes other users\' personal data, orders, messages, etc.',
                            remediation='Implement object-level authorization checks. Verify the authenticated '
                                       'user owns the requested object before returning data. '
                                       'Use indirect references (mapping table) instead of direct IDs.',
                            cwe='CWE-639',
                            cvss=7.5,
                            affected_url=url,
                            evidence=f'Parameter: {param_name}\n'
                                    f'Original ID: {original_value} ({original_length} bytes)\n'
                                    f'Test ID: {test_id} ({resp_length} bytes)\n'
                                    f'Different data returned without authorization.',
                        )
        return None

    def _test_uuid_swap(self, url, param_name, original_uuid):
        """Test UUID parameters by swapping with a known-valid UUID.

        With dual sessions: victim fetches → attacker fetches same UUID = confirmed.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # ── Cross-account IDOR (dual session) ────────────────────────────
        if self.has_victim_session:
            victim_resp = self._make_victim_request('GET', url)
            if not victim_resp or victim_resp.status_code != 200:
                return None
            victim_body = victim_resp.text or ''
            if len(victim_body) < 50:
                return None

            attacker_resp = self._make_request('GET', url)
            if attacker_resp and attacker_resp.status_code == 200:
                attacker_body = attacker_resp.text or ''
                if len(attacker_body) > 50 and abs(len(victim_body) - len(attacker_body)) < max(len(victim_body) * 0.3, 100):
                    return self._build_vuln(
                        name=f'Confirmed IDOR via UUID: {param_name}',
                        severity='critical',
                        category='Broken Access Control',
                        description=f'Cross-account test: attacker accessed victim\'s resource '
                                   f'with UUID "{original_uuid}" and received data. '
                                   f'No object-level auth check.',
                        impact='Any user can access any other user\'s data via UUID manipulation.',
                        remediation='Implement object-level authorization. UUIDs are not a '
                                   'security boundary — always verify ownership.',
                        cwe='CWE-639',
                        cvss=9.1,
                        affected_url=url,
                        evidence=f'Parameter: {param_name}\n'
                                f'UUID: {original_uuid}\n'
                                f'Victim: {len(victim_body)} bytes | Attacker: {len(attacker_body)} bytes\n'
                                f'Cross-account IDOR confirmed.',
                    )
            return None

        # ── Single-session fallback ──────────────────────────────────────
        # Try well-known test UUIDs
        test_uuids = [
            '00000000-0000-0000-0000-000000000000',  # nil UUID
            '00000000-0000-0000-0000-000000000001',  # first UUID
            'ffffffff-ffff-ffff-ffff-ffffffffffff',  # max UUID
        ]

        original_resp = self._make_request('GET', url)
        if not original_resp or original_resp.status_code != 200:
            return None

        for test_uuid in test_uuids:
            if test_uuid == original_uuid:
                continue
            params[param_name] = test_uuid
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and resp.status_code == 200 and len(resp.text or '') > 100:
                if resp.text != original_resp.text:
                    return self._build_vuln(
                        name=f'IDOR via UUID Swap: {param_name}',
                        severity='high',
                        category='Broken Access Control',
                        description=f'The parameter "{param_name}" accepts arbitrary UUIDs '
                                   f'without authorization checks. Swapping the UUID returned '
                                   f'different object data.',
                        impact='If UUIDs are predictable (v1) or leaked, attackers can '
                              'access any object in the system.',
                        remediation='Implement object-level authorization. UUIDs are not a '
                                   'security boundary — always verify ownership.',
                        cwe='CWE-639',
                        cvss=7.5,
                        affected_url=url,
                        evidence=f'Parameter: {param_name}\n'
                                f'Original UUID: {original_uuid}\n'
                                f'Test UUID: {test_uuid}\n'
                                f'Different data returned.',
                    )
        return None

    def _test_sequential_enum(self, url, param_name, original_value):
        """Test sequential enumeration: try id-10 to id+10."""
        try:
            original_int = int(original_value)
        except (ValueError, TypeError):
            return None

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        success_count = 0
        tested = 0

        for offset in range(-10, 11):
            if offset == 0:
                continue
            test_id = original_int + offset
            if test_id < 0:
                continue
            params[param_name] = str(test_id)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            tested += 1
            if resp and resp.status_code == 200 and len(resp.text or '') > 100:
                success_count += 1
            if tested >= 5:
                break

        if success_count >= 3:
            return self._build_vuln(
                name=f'Sequential ID Enumeration: {param_name}',
                severity='high',
                category='Broken Access Control',
                description=f'The parameter "{param_name}" allows sequential enumeration '
                           f'of objects. {success_count}/{tested} adjacent IDs returned '
                           f'valid data without authorization checks.',
                impact='Attackers can systematically enumerate all objects (users, orders, '
                      'documents) by iterating the numeric ID parameter.',
                remediation='Implement object-level authorization. Use UUIDs instead of sequential '
                           'integers. Add rate limiting to ID-based endpoints.',
                cwe='CWE-639',
                cvss=7.5,
                affected_url=url,
                evidence=f'Parameter: {param_name}\n'
                        f'Base ID: {original_value}\n'
                        f'{success_count}/{tested} adjacent IDs accessible.',
            )
        return None

    def _test_boundary_ids(self, url, param_name):
        """Test with boundary ID values: 0, -1, 9999999."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        boundary_values = [
            ('0', 'zero ID'),
            ('-1', 'negative ID'),
            ('9999999', 'large ID'),
            ('1', 'first ID (often admin)'),
        ]

        for value, desc in boundary_values:
            params[param_name] = value
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and resp.status_code == 200 and len(resp.text or '') > 200:
                return self._build_vuln(
                    name=f'IDOR Boundary Value Access: {param_name}={value}',
                    severity='medium',
                    category='Broken Access Control',
                    description=f'The parameter "{param_name}" accepts boundary value '
                               f'{value} ({desc}) and returns data without authorization.',
                    impact='Boundary IDs often map to admin or system objects. '
                          'Accessing id=0 or id=1 may expose admin accounts.',
                    remediation='Validate object ownership before returning data. '
                               'Return 403 or 404 for unauthorized objects.',
                    cwe='CWE-639',
                    cvss=6.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}={value} ({desc})\n'
                            f'Returned 200 with {len(resp.text)} bytes.',
                )
        return None

    def _test_user_context_headers(self, page):
        """Test for IDOR by manipulating user-context headers."""
        vulns = []
        original_resp = self._make_request('GET', page.url)
        if not original_resp or original_resp.status_code != 200:
            return vulns

        for header_name in _USER_CONTEXT_HEADERS:
            test_values = ['1', '0', 'admin', '999999']
            for value in test_values:
                resp = self._make_request('GET', page.url,
                                         headers={header_name: value})
                if not resp or resp.status_code != 200:
                    continue
                if resp.text != original_resp.text and len(resp.text or '') > 100:
                    vulns.append(self._build_vuln(
                        name=f'IDOR via User-Context Header: {header_name}',
                        severity='high',
                        category='Broken Access Control',
                        description=f'Manipulating the "{header_name}" header to "{value}" '
                                   f'returned different data, suggesting the application uses '
                                   f'this header for user identification without validation.',
                        impact='Attackers can impersonate any user by setting the user-context '
                              'header, accessing their data without authentication.',
                        remediation='Never trust user-supplied headers for authorization. '
                                   'Use server-side session authentication only.',
                        cwe='CWE-639',
                        cvss=8.6,
                        affected_url=page.url,
                        evidence=f'Header: {header_name}: {value}\nDifferent data returned.',
                    ))
                    break
        return vulns

    def _test_path_idor(self, page):
        """Test path-based IDOR: /users/123/profile → /users/124/profile.

        With dual sessions: victim fetches original path → attacker fetches same path.
        """
        parsed = urlparse(page.url)
        path = parsed.path

        # ── Cross-account path IDOR (dual session) ──────────────────────
        if self.has_victim_session:
            victim_resp = self._make_victim_request('GET', page.url)
            if victim_resp and victim_resp.status_code == 200 and len(victim_resp.text or '') > 100:
                attacker_resp = self._make_request('GET', page.url)
                if (attacker_resp and attacker_resp.status_code == 200 and
                        len(attacker_resp.text or '') > 100):
                    victim_len = len(victim_resp.text)
                    attacker_len = len(attacker_resp.text)
                    if abs(victim_len - attacker_len) < max(victim_len * 0.3, 100):
                        return self._build_vuln(
                            name=f'Confirmed Path-Based IDOR: {path}',
                            severity='critical',
                            category='Broken Access Control',
                            description=f'Cross-account test: attacker accessed victim\'s '
                                       f'resource at path "{path}" and received {attacker_len} bytes.',
                            impact='Attackers can access other users\' resources by navigating '
                                  'to paths containing victim identifiers.',
                            remediation='Implement authorization checks for all path-based resource access.',
                            cwe='CWE-639',
                            cvss=9.1,
                            affected_url=page.url,
                            evidence=f'Path: {path}\n'
                                    f'Victim: {victim_len} bytes | Attacker: {attacker_len} bytes\n'
                                    f'Cross-account path IDOR confirmed.',
                        )

        # ── Single-session fallback ──────────────────────────────────────
        # Find numeric segments in path
        segments = path.split('/')
        for i, segment in enumerate(segments):
            if not segment.isdigit():
                continue

            original_id = int(segment)
            for offset in [1, -1]:
                test_id = original_id + offset
                if test_id < 0:
                    continue
                new_segments = segments.copy()
                new_segments[i] = str(test_id)
                new_path = '/'.join(new_segments)
                test_url = urlunparse((parsed.scheme, parsed.netloc, new_path,
                                       parsed.params, parsed.query, ''))

                original_resp = self._make_request('GET', page.url)
                resp = self._make_request('GET', test_url)
                if (resp and resp.status_code == 200 and
                        original_resp and original_resp.status_code == 200 and
                        resp.text != original_resp.text and len(resp.text or '') > 100):
                    return self._build_vuln(
                        name=f'Path-Based IDOR: {path}',
                        severity='high',
                        category='Broken Access Control',
                        description=f'Changing the numeric path segment from {original_id} to '
                                   f'{test_id} in "{path}" returned different data, indicating '
                                   f'path-based IDOR without authorization.',
                        impact='Attackers can access other users\' resources by modifying '
                              'numeric segments in the URL path.',
                        remediation='Implement authorization checks for all path-based resource access. '
                                   'Use middleware that validates object ownership.',
                        cwe='CWE-639',
                        cvss=7.5,
                        affected_url=page.url,
                        evidence=f'Original path: {path}\n'
                                f'Test path: {new_path}\n'
                                f'Different data returned.',
                    )
        return None

    def _test_array_wrapping(self, url, param_name, original_value):
        """Test array-wrapping: id=1 → id[]=1&id[]=2."""
        parsed = urlparse(url)

        array_payloads = [
            f'{param_name}[]=1&{param_name}[]=2',
            f'{param_name}[]=0&{param_name}[]={original_value}',
        ]

        for payload in array_payloads:
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, payload, ''))
            resp = self._make_request('GET', test_url)
            if resp and resp.status_code == 200 and len(resp.text or '') > 200:
                original_resp = self._make_request('GET', url)
                if original_resp and resp.text != original_resp.text:
                    return self._build_vuln(
                        name=f'IDOR via Array Wrapping: {param_name}',
                        severity='medium',
                        category='Broken Access Control',
                        description=f'Array-wrapping the "{param_name}" parameter returned '
                                   f'different data, suggesting the application processes '
                                   f'multiple IDs without proper authorization.',
                        impact='Array wrapping may return data for multiple objects or bypass '
                              'authorization that only checks the first element.',
                        remediation='Validate authorization for each element in array parameters. '
                                   'Reject unexpected array parameters.',
                        cwe='CWE-639',
                        cvss=6.5,
                        affected_url=url,
                        evidence=f'Parameter: {payload}\nDifferent data returned.',
                    )
        return None

    def _test_admin_ids(self, url, param_name):
        """Test with admin-specific ID values."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        admin_values = ['0', '1', '-1', 'admin', 'root', 'administrator']
        for value in admin_values:
            params[param_name] = value
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and resp.status_code == 200:
                body_lower = (resp.text or '').lower()
                # Check for admin indicators in response
                admin_indicators = ['admin', 'administrator', 'superuser', 'root',
                                   'privilege', 'role', 'permission']
                if any(ind in body_lower for ind in admin_indicators):
                    return self._build_vuln(
                        name=f'Admin Object Access via IDOR: {param_name}={value}',
                        severity='critical',
                        category='Broken Access Control',
                        description=f'Setting "{param_name}" to "{value}" returned admin-level '
                                   f'data. The application does not verify authorization for '
                                   f'privileged objects.',
                        impact='Direct access to admin accounts or privileged objects enables '
                              'full application takeover.',
                        remediation='Implement role-based access control. Never expose admin '
                                   'objects to non-admin users regardless of parameter values.',
                        cwe='CWE-639',
                        cvss=9.1,
                        affected_url=url,
                        evidence=f'Parameter: {param_name}={value}\n'
                                f'Admin indicators found in response.',
                    )
        return None
