"""
HTTP Parameter Pollution Tester — Detects HPP vulnerabilities.

Covers:
  - Duplicate parameter injection
  - Parameter precedence exploitation per server type
  - HPP in forms, query strings, and POST data
"""
import logging
import urllib.parse

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Server-specific parameter handling ───────────────────────────────────────
# Different servers handle duplicate parameters differently:
#   PHP/Apache:  last occurrence wins
#   ASP.NET/IIS: all values comma-joined
#   JSP/Tomcat:  first occurrence wins
#   Python/Flask: first occurrence wins
#   Node/Express: array of values (first by default)

HPP_TEST_MARKER = 'hpptest42'

# ── Common security-sensitive parameters ─────────────────────────────────────
SENSITIVE_PARAMS = [
    'redirect', 'redirect_uri', 'url', 'callback',
    'email', 'user', 'username', 'to', 'from', 'cc',
    'id', 'uid', 'user_id', 'account',
    'amount', 'price', 'total', 'quantity',
    'role', 'admin', 'access', 'permission',
    'action', 'cmd', 'command', 'type',
    'token', 'csrf', 'nonce', 'code',
]

# ── HPP bypass payloads ─────────────────────────────────────────────────────
HPP_SEPARATOR_VARIANTS = [
    ('&', 'Standard duplicate'),        # ?p=val1&p=val2
    (';', 'Semicolon separator'),        # ?p=val1;p=val2
    ('%26', 'URL-encoded ampersand'),    # ?p=val1%26p=val2
]


class HPPTester(BaseTester):
    """Test for HTTP Parameter Pollution vulnerabilities."""

    TESTER_NAME = 'HTTP Parameter Pollution'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        getattr(page, 'body', '') or ''
        params = getattr(page, 'parameters', {}) or {}
        forms = getattr(page, 'forms', []) or []

        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)

        if not qs and not params and not forms:
            return vulns

        # 1. Test duplicate parameter injection in URL
        vuln = self._test_url_hpp(url, parsed, qs)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Test HPP on security-sensitive parameters
        vuln = self._test_sensitive_param_hpp(url, parsed, qs, params)
        if vuln:
            vulns.append(vuln)

        if depth == 'deep':
            # 3. Test HPP in form parameters
            for form in forms[:2]:
                vuln = self._test_form_hpp(url, form)
                if vuln:
                    vulns.append(vuln)
                    break

        return vulns

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _test_url_hpp(self, url: str, parsed, qs: dict):
        """Test if duplicate parameters cause different behavior."""
        if not qs:
            return None

        # Pick the first parameter to test
        param_name = list(qs.keys())[0]
        original_value = qs[param_name][0]

        # Send with duplicate parameter: original + evil value
        test_query = urllib.parse.urlencode(
            {param_name: original_value}
        ) + f'&{param_name}={HPP_TEST_MARKER}'
        test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

        try:
            resp_original = self._make_request('GET', url)
            resp_hpp = self._make_request('GET', test_url)

            if not resp_original or not resp_hpp:
                return None

            getattr(resp_original, 'text', '')
            hpp_body = getattr(resp_hpp, 'text', '')

            # Check if our marker appears in the response
            if HPP_TEST_MARKER in hpp_body:
                return self._build_vuln(
                    name='HTTP Parameter Pollution',
                    severity='medium',
                    category='Injection',
                    description=(
                        f'Duplicate parameter "{param_name}" is reflected in the '
                        'response. The server processes duplicate parameters, which '
                        'can be exploited to bypass security filters or alter '
                        'application logic.'
                    ),
                    impact='Security filter bypass, WAF evasion, logic manipulation',
                    remediation=(
                        'Reject requests with duplicate parameters or explicitly '
                        'choose first/last occurrence consistently. Validate parameters '
                        'after parsing.'
                    ),
                    cwe='CWE-235',
                    cvss=5.3,
                    affected_url=test_url,
                    evidence=f'Duplicate param "{param_name}" reflected: ...{HPP_TEST_MARKER}...',
                )

            # Check if behavior changed significantly
            if (resp_original.status_code != resp_hpp.status_code
                    and resp_hpp.status_code not in (400, 403, 422)):
                return self._build_vuln(
                    name='HTTP Parameter Pollution - Behavior Change',
                    severity='medium',
                    category='Injection',
                    description=(
                        f'Adding a duplicate "{param_name}" parameter changed the '
                        f'response status from {resp_original.status_code} to '
                        f'{resp_hpp.status_code}, indicating HPP vulnerability.'
                    ),
                    impact='Application logic manipulation via parameter pollution',
                    remediation='Validate and deduplicate parameters server-side.',
                    cwe='CWE-235',
                    cvss=5.3,
                    affected_url=test_url,
                    evidence=(
                        f'Status changed: {resp_original.status_code} → '
                        f'{resp_hpp.status_code} with duplicate {param_name}'
                    ),
                )
        except Exception:
            pass
        return None

    def _test_sensitive_param_hpp(self, url: str, parsed, qs: dict,
                                  params: dict):
        """Test HPP on security-sensitive parameters."""
        all_params = set(qs.keys()) | set(params.keys())
        sensitive = [p for p in all_params if p.lower() in SENSITIVE_PARAMS]

        for param_name in sensitive[:3]:
            original_value = (
                qs.get(param_name, [''])[0]
                or str(params.get(param_name, ''))
            )

            test_values = {
                'email': 'evil@example.com',
                'role': 'admin',
                'admin': 'true',
                'amount': '0',
                'price': '0.01',
                'redirect': 'https://evil.example.com',
                'redirect_uri': 'https://evil.example.com',
            }
            evil_value = test_values.get(param_name.lower(), HPP_TEST_MARKER)

            # Test: original param + appended duplicate
            test_query = urllib.parse.urlencode(
                {param_name: original_value}
            ) + f'&{param_name}={urllib.parse.quote(evil_value)}'
            test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

            try:
                resp = self._make_request('GET', test_url)
                if resp and resp.status_code in (200, 302):
                    resp_body = getattr(resp, 'text', '')
                    location = resp.headers.get('Location', '')

                    if evil_value in resp_body or evil_value in location:
                        return self._build_vuln(
                            name='HPP on Security-Sensitive Parameter',
                            severity='high',
                            category='Injection',
                            description=(
                                f'The security-sensitive parameter "{param_name}" '
                                'is pollutable. Injecting a duplicate with a malicious '
                                'value results in the evil value being used.'
                            ),
                            impact='Parameter manipulation, access control bypass, redirect abuse',
                            remediation=(
                                f'Explicitly validate "{param_name}" and reject '
                                'duplicate parameter submissions.'
                            ),
                            cwe='CWE-235',
                            cvss=7.3,
                            affected_url=test_url,
                            evidence=f'Evil value "{evil_value}" used for "{param_name}"',
                        )
            except Exception:
                continue
        return None

    def _test_form_hpp(self, url: str, form):
        """Test HPP in form submissions."""
        action = getattr(form, 'action', '') or url
        method = getattr(form, 'method', 'POST').upper()
        inputs = getattr(form, 'inputs', []) or []

        if not inputs:
            return None

        target_input = None
        for inp in inputs:
            inp_name = getattr(inp, 'name', '')
            if inp_name.lower() in SENSITIVE_PARAMS:
                target_input = inp
                break
        if not target_input:
            target_input = inputs[0]

        inp_name = getattr(target_input, 'name', '')
        if not inp_name:
            return None

        original_value = getattr(target_input, 'value', '') or 'test'
        # Build form data with duplicate parameter
        data = f'{inp_name}={original_value}&{inp_name}={HPP_TEST_MARKER}'

        try:
            resp = self._make_request(
                method, action,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            if resp and resp.status_code in (200, 302):
                resp_body = getattr(resp, 'text', '')
                if HPP_TEST_MARKER in resp_body:
                    return self._build_vuln(
                        name='HPP in Form Submission',
                        severity='medium',
                        category='Injection',
                        description=(
                            f'Form parameter "{inp_name}" is vulnerable to HTTP '
                            'Parameter Pollution via duplicate POST parameters.'
                        ),
                        impact='Form logic bypass, security control evasion',
                        remediation='Reject forms with duplicate parameters. Validate at server.',
                        cwe='CWE-235',
                        cvss=5.3,
                        affected_url=action,
                        evidence=f'Duplicate form param "{inp_name}" reflected',
                    )
        except Exception:
            pass
        return None
