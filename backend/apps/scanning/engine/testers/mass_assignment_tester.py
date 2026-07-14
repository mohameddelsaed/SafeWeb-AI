"""
MassAssignmentTester — Mass assignment / parameter binding vulnerability detection.
OWASP API3:2023 — Broken Object Property Level Authorization.

Tests for: extra JSON key injection, framework-specific bypasses (Rails, Django,
Mongoose), nested object injection, and numeric privilege escalation.
"""
import json
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Common privilege escalation keys
_PRIV_KEYS_SHALLOW = ['is_admin', 'role', 'admin', 'privilege', 'isAdmin',
                       'user_type', 'is_staff', 'is_superuser', 'permissions']

# Extended keys for medium depth (common AR/Django/ORM fields)
_PRIV_KEYS_MEDIUM = ['_destroy', 'active', 'confirmed', 'locked', 'password',
                      'email', 'verified', 'approved', 'banned', 'suspended',
                      'credits', 'balance', 'plan', 'tier', 'subscription']


class MassAssignmentTester(BaseTester):
    """Test for mass assignment / parameter binding vulnerabilities."""

    TESTER_NAME = 'MassAssignment'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        for form in page.forms:
            if form.method.upper() not in ('POST', 'PUT', 'PATCH'):
                continue

            target_url = form.action or page.url

            # Shallow: inject extra privilege keys
            vuln = self._test_extra_keys(form, target_url, _PRIV_KEYS_SHALLOW)
            if vuln:
                vulnerabilities.append(vuln)
                continue

            # Medium: extended ORM field injection
            if depth in ('medium', 'deep'):
                vuln = self._test_extra_keys(form, target_url, _PRIV_KEYS_MEDIUM)
                if vuln:
                    vulnerabilities.append(vuln)
                    continue

                # Array-wrapped values
                vuln = self._test_array_wrapped(form, target_url)
                if vuln:
                    vulnerabilities.append(vuln)
                    continue

                # Nested object injection
                vuln = self._test_nested_objects(form, target_url)
                if vuln:
                    vulnerabilities.append(vuln)
                    continue

            # Deep: framework-specific bypasses
            if depth == 'deep':
                vuln = self._test_framework_specific(form, target_url, recon_data)
                if vuln:
                    vulnerabilities.append(vuln)
                    continue

                vuln = self._test_numeric_escalation(form, target_url)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_extra_keys(self, form, target_url, extra_keys):
        """Add extra JSON keys to form submission and check if reflected."""
        # Build base form data
        base_data = {}
        for inp in form.inputs:
            if inp.name and inp.input_type not in ('submit', 'button', 'image'):
                base_data[inp.name] = inp.value or 'test'

        for key in extra_keys:
            if key in base_data:
                continue

            # Test with JSON body
            json_data = dict(base_data)
            json_data[key] = True if 'is_' in key or key.startswith('is') else 'admin'

            resp = self._make_request(
                form.method.upper(), target_url,
                json=json_data,
                headers={'Content-Type': 'application/json'},
            )
            if not resp:
                continue

            # Check if the extra key is reflected in response
            resp_text = resp.text or ''
            if resp.status_code in (200, 201) and key in resp_text:
                # Verify it's not just an error message echoing the key
                try:
                    resp_json = resp.json()
                    if key in resp_json or any(key in str(v) for v in resp_json.values()
                                               if isinstance(resp_json, dict)):
                        return self._build_vuln(
                            name=f'Mass Assignment: {key} accepted at {target_url}',
                            severity='high',
                            category='Broken Access Control',
                            description=f'The endpoint accepted and reflected the extra key "{key}" '
                                       f'in a {form.method.upper()} request. The application binds '
                                       f'request parameters directly to model attributes without filtering.',
                            impact='Attackers can escalate privileges by adding admin/role parameters, '
                                  'modify protected fields, or bypass business logic constraints.',
                            remediation='Use allowlists for accepted parameters. In Django: use serializer '
                                       'fields explicitly. In Rails: use strong_params. In Express: validate '
                                       'with Joi/Zod. Never pass raw request body to model.update().',
                            cwe='CWE-915',
                            cvss=8.1,
                            affected_url=target_url,
                            evidence=f'Extra key: {key}\n'
                                    f'Value sent: {json_data[key]}\n'
                                    f'Key reflected in response body.',
                        )
                except (json.JSONDecodeError, ValueError, AttributeError):
                    pass

            # Also test with form-encoded data
            form_data = dict(base_data)
            form_data[key] = 'true' if 'is_' in key or key.startswith('is') else 'admin'
            resp = self._make_request(form.method.upper(), target_url, data=form_data)
            if resp and resp.status_code in (200, 201) and key in (resp.text or ''):
                return self._build_vuln(
                    name=f'Mass Assignment (Form): {key} accepted at {target_url}',
                    severity='high',
                    category='Broken Access Control',
                    description=f'The endpoint accepted the extra form field "{key}" in a '
                               f'{form.method.upper()} request, indicating mass assignment vulnerability.',
                    impact='Privilege escalation via extra form parameters.',
                    remediation='Implement parameter allowlists. Never bind raw request data to models.',
                    cwe='CWE-915',
                    cvss=8.1,
                    affected_url=target_url,
                    evidence=f'Extra field: {key}={form_data[key]}\nReflected in response.',
                )
        return None

    def _test_array_wrapped(self, form, target_url):
        """Test array-wrapped privilege escalation: role[]=admin."""
        base_data = {}
        for inp in form.inputs:
            if inp.name and inp.input_type not in ('submit', 'button', 'image'):
                base_data[inp.name] = inp.value or 'test'

        array_payloads = [
            {'role[]': 'admin'},
            {'permissions[]': 'all'},
            {'groups[]': 'administrators'},
        ]

        for extra in array_payloads:
            form_data = dict(base_data)
            form_data.update(extra)
            resp = self._make_request(form.method.upper(), target_url, data=form_data)
            if resp and resp.status_code in (200, 201):
                key = list(extra.keys())[0]
                if key.rstrip('[]') in (resp.text or ''):
                    return self._build_vuln(
                        name=f'Mass Assignment (Array): {key} at {target_url}',
                        severity='high',
                        category='Broken Access Control',
                        description=f'Array-wrapped parameter "{key}" was accepted and reflected, '
                                   f'suggesting mass assignment via array binding.',
                        impact='Array-wrapped parameters may bypass allowlist checks that only '
                              'filter scalar parameter names.',
                        remediation='Validate parameter types and reject unexpected arrays. '
                                   'Use strict schema validation.',
                        cwe='CWE-915',
                        cvss=7.5,
                        affected_url=target_url,
                        evidence=f'Array parameter: {extra}\nAccepted by endpoint.',
                    )
        return None

    def _test_nested_objects(self, form, target_url):
        """Test nested object injection: user[role]=admin."""
        base_data = {}
        for inp in form.inputs:
            if inp.name and inp.input_type not in ('submit', 'button', 'image'):
                base_data[inp.name] = inp.value or 'test'

        nested_payloads = [
            {'user[role]': 'admin', 'user[is_admin]': 'true'},
            {'account[type]': 'premium', 'account[plan]': 'enterprise'},
            {'profile[role]': 'administrator'},
        ]

        for extra in nested_payloads:
            form_data = dict(base_data)
            form_data.update(extra)
            resp = self._make_request(form.method.upper(), target_url, data=form_data)
            if resp and resp.status_code in (200, 201):
                resp_text = (resp.text or '').lower()
                if any(v.lower() in resp_text for v in extra.values()):
                    key = list(extra.keys())[0]
                    return self._build_vuln(
                        name=f'Mass Assignment (Nested): {key} at {target_url}',
                        severity='high',
                        category='Broken Access Control',
                        description=f'Nested object parameter "{key}" was accepted and its value '
                                   f'reflected, indicating mass assignment via nested binding.',
                        impact='Nested object injection can modify deeply nested model attributes '
                              'that are not protected by top-level parameter filtering.',
                        remediation='Implement deep parameter validation. Use allowlists that cover '
                                   'nested attributes. Reject unexpected nested structures.',
                        cwe='CWE-915',
                        cvss=7.5,
                        affected_url=target_url,
                        evidence=f'Nested params: {extra}\nValues reflected in response.',
                    )
        return None

    def _test_framework_specific(self, form, target_url, recon_data):
        """Test framework-specific mass assignment bypasses."""
        base_data = {}
        for inp in form.inputs:
            if inp.name and inp.input_type not in ('submit', 'button', 'image'):
                base_data[inp.name] = inp.value or 'test'

        framework_payloads = [
            # Rails strong_params bypass via _json suffix
            {'user_json': json.dumps({'role': 'admin', 'is_admin': True}),
             'desc': 'Rails _json suffix bypass'},
            # Mongoose __proto__ pollution
            {'__proto__[isAdmin]': 'true',
             'desc': 'Mongoose prototype pollution'},
            {'constructor[prototype][isAdmin]': 'true',
             'desc': 'Constructor prototype pollution'},
        ]

        for payload_set in framework_payloads:
            desc = payload_set.pop('desc')
            form_data = dict(base_data)
            form_data.update(payload_set)
            resp = self._make_request(form.method.upper(), target_url, data=form_data)
            payload_set['desc'] = desc  # restore

            if resp and resp.status_code in (200, 201):
                resp_text = (resp.text or '').lower()
                if 'admin' in resp_text or 'true' in resp_text:
                    return self._build_vuln(
                        name=f'Framework-Specific Mass Assignment: {desc}',
                        severity='critical',
                        category='Broken Access Control',
                        description=f'A framework-specific mass assignment bypass ({desc}) was '
                                   f'detected at {target_url}.',
                        impact='Framework-specific bypasses can circumvent standard mass assignment '
                              'protections, enabling privilege escalation.',
                        remediation='Update framework to latest version. Use strict parameter '
                                   'validation independent of framework defaults. '
                                   'Implement defense-in-depth with multiple validation layers.',
                        cwe='CWE-915',
                        cvss=9.1,
                        affected_url=target_url,
                        evidence=f'Technique: {desc}\nPayload: {payload_set}\n'
                                f'Response indicated success.',
                    )
        return None

    def _test_numeric_escalation(self, form, target_url):
        """Test numeric privilege escalation: role=999, privilege=9999."""
        base_data = {}
        for inp in form.inputs:
            if inp.name and inp.input_type not in ('submit', 'button', 'image'):
                base_data[inp.name] = inp.value or 'test'

        numeric_payloads = [
            {'role': '999', 'desc': 'High numeric role'},
            {'privilege': '9999', 'desc': 'High numeric privilege'},
            {'level': '100', 'desc': 'High numeric level'},
            {'access_level': '99', 'desc': 'High access level'},
        ]

        for payload_set in numeric_payloads:
            desc = payload_set.pop('desc')
            json_data = dict(base_data)
            json_data.update(payload_set)
            resp = self._make_request(
                form.method.upper(), target_url,
                json=json_data,
                headers={'Content-Type': 'application/json'},
            )
            payload_set['desc'] = desc

            if resp and resp.status_code in (200, 201):
                key = list(payload_set.keys())[0]
                if key != 'desc' and key in (resp.text or ''):
                    return self._build_vuln(
                        name=f'Numeric Privilege Escalation: {key}={payload_set[key]}',
                        severity='high',
                        category='Broken Access Control',
                        description=f'A high numeric value for "{key}" was accepted, potentially '
                                   f'escalating privileges via numeric role/privilege assignment.',
                        impact='Numeric privilege levels may grant admin access when set to '
                              'maximum or unexpected values.',
                        remediation='Validate privilege levels against allowed values. '
                                   'Use enum types instead of numeric privilege levels.',
                        cwe='CWE-915',
                        cvss=8.1,
                        affected_url=target_url,
                        evidence=f'Key: {key}={payload_set[key]} ({desc})\n'
                                f'Accepted by endpoint.',
                    )
        return None
