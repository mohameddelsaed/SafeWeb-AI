"""
ReDoS Tester — Detects Regular Expression Denial of Service vulnerabilities.

Covers:
  - Detecting reflected regex patterns in responses
  - Time-based ReDoS detection with evil inputs
  - Common vulnerable regex patterns in input validation
"""
import logging
import re
import time

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Evil inputs that cause exponential backtracking on common regexes ────────
REDOS_PAYLOADS = [
    {
        'name': 'nested_quantifier',
        'payload': 'a' * 40 + '!',
        'description': 'Triggers (a+)+ style nested quantifier backtracking',
    },
    {
        'name': 'overlapping_alternation',
        'payload': 'a' * 30 + 'X',
        'description': 'Triggers (a|a)+ overlapping alternation backtracking',
    },
    {
        'name': 'email_validation',
        'payload': 'a' * 25 + '@' + 'a' * 25 + '.' + 'a' * 25 + '!',
        'description': 'Triggers backtracking in loose email regexes',
    },
    {
        'name': 'url_validation',
        'payload': 'http://' + 'a' * 40 + '.' + 'a' * 40 + '!',
        'description': 'Triggers backtracking in URL validation patterns',
    },
    {
        'name': 'whitespace_exploitation',
        'payload': ' \t' * 30 + '!',
        'description': 'Triggers (\\s+)+ or similar whitespace backtracking',
    },
]

# ── Patterns that signal server-side regex validation ────────────────────────
REGEX_ERROR_PATTERNS = re.compile(
    r'(?:'
    r'invalid\s+format'
    r'|pattern\s+(?:does\s+not\s+match|mismatch)'
    r'|must\s+match\s+(?:the\s+)?(?:pattern|regex|format)'
    r'|regular\s+expression'
    r'|does\s+not\s+match\s+the\s+required\s+pattern'
    r'|validation\s+(?:error|failed)'
    r'|format\s+(?:error|invalid)'
    r')',
    re.IGNORECASE,
)

# ── Endpoints likely to have regex validation ────────────────────────────────
VALIDATE_ENDPOINT_PATTERNS = [
    r'/register', r'/signup', r'/validate', r'/verify',
    r'/check', r'/search', r'/filter', r'/api/',
    r'/profile', r'/settings', r'/update',
]

# ── Form fields likely to have regex validation ──────────────────────────────
VALIDATED_FIELDS = [
    'email', 'phone', 'url', 'website', 'zip', 'zipcode',
    'postal', 'postcode', 'pattern', 'regex', 'format',
    'username', 'name', 'address', 'ssn', 'credit_card',
    'card_number', 'ip', 'domain', 'hostname',
]

# ── Time threshold for ReDoS detection (seconds) ────────────────────────────
REDOS_TIME_THRESHOLD = 2.0
REDOS_BASELINE_MULTIPLIER = 5.0


class ReDoSTester(BaseTester):
    """Test for Regular Expression Denial of Service vulnerabilities."""

    TESTER_NAME = 'ReDoS'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        forms = getattr(page, 'forms', []) or []
        params = getattr(page, 'parameters', {}) or {}

        has_validation = self._has_validation_endpoint(url)

        # 1. Check for regex error messages in page body (light check)
        vuln = self._check_regex_error_exposure(url, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Test form fields for ReDoS
        if forms:
            form_vulns = self._test_form_redos(url, forms)
            vulns.extend(form_vulns)

        if depth == 'medium' and len(vulns) > 0:
            return vulns

        # 3. Test URL parameters for ReDoS (deeper)
        if params and has_validation:
            param_vulns = self._test_param_redos(url, params)
            vulns.extend(param_vulns)

        return vulns

    # ── Detection helpers ────────────────────────────────────────────────────

    def _has_validation_endpoint(self, url: str) -> bool:
        for pattern in VALIDATE_ENDPOINT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_regex_error_exposure(self, url: str, body: str):
        """Check if response exposes regex pattern information."""
        # Look for actual regex patterns leaked in error messages
        regex_leak = re.search(
            r'(?:pattern|regex|regexp)[\s:=]*["\']?'
            r'([/^](?:[^"\'<>\n]{5,80})[$/]?)'
            r'["\']?',
            body,
            re.IGNORECASE,
        )
        if regex_leak:
            return self._build_vuln(
                name='Regex Pattern Information Disclosure',
                severity='low',
                category='Information Disclosure',
                description=(
                    'The server exposes regex validation patterns in the response. '
                    'This allows attackers to craft inputs that cause backtracking.'
                ),
                impact='Enables targeted ReDoS attacks via exposed patterns',
                remediation='Do not expose regex patterns in error messages.',
                cwe='CWE-200',
                cvss=3.7,
                affected_url=url,
                evidence=f'Leaked pattern: {regex_leak.group(1)[:80]}',
            )
        return None

    def _test_form_redos(self, url: str, forms: list) -> list:
        """Test form fields with ReDoS payloads using time-based detection."""
        vulns = []
        for form in forms[:2]:
            action = getattr(form, 'action', '') or url
            method = getattr(form, 'method', 'POST').upper()
            inputs = getattr(form, 'inputs', []) or []

            # Find fields likely to have regex validation
            target_fields = []
            for inp in inputs:
                inp_name = getattr(inp, 'name', '') or ''
                inp_type = getattr(inp, 'input_type', '') or ''
                if (inp_name.lower() in VALIDATED_FIELDS
                        or inp_type in ('email', 'url', 'tel', 'pattern')):
                    target_fields.append(inp)

            if not target_fields:
                continue

            for field in target_fields[:2]:
                field_name = getattr(field, 'name', '')
                vuln = self._time_based_redos_test(
                    action, method, inputs, field_name,
                )
                if vuln:
                    vulns.append(vuln)
                    break  # One per form is enough
        return vulns

    def _test_param_redos(self, url: str, params: dict) -> list:
        """Test URL parameters for ReDoS."""
        vulns = []
        for param_name, param_val in list(params.items())[:3]:
            if param_name.lower() in VALIDATED_FIELDS:
                vuln = self._time_based_param_redos(url, param_name)
                if vuln:
                    vulns.append(vuln)
                    break
        return vulns

    def _time_based_redos_test(self, action: str, method: str,
                               inputs: list, target_field: str):
        """Send benign vs evil inputs and compare response times."""
        # Build baseline data
        base_data = {}
        for inp in inputs:
            inp_name = getattr(inp, 'name', '')
            if inp_name == target_field:
                base_data[inp_name] = 'normal_value'
            elif inp_name:
                base_data[inp_name] = getattr(inp, 'value', '') or 'test'

        # Measure baseline
        try:
            t0 = time.monotonic()
            self._make_request(method, action, data=base_data)
            baseline_time = time.monotonic() - t0
        except Exception:
            return None

        # Test with each ReDoS payload
        for payload_info in REDOS_PAYLOADS[:3]:
            evil_data = dict(base_data)
            evil_data[target_field] = payload_info['payload']

            try:
                t0 = time.monotonic()
                self._make_request(method, action, data=evil_data)
                elapsed = time.monotonic() - t0

                if (elapsed > REDOS_TIME_THRESHOLD
                        and elapsed > baseline_time * REDOS_BASELINE_MULTIPLIER):
                    return self._build_vuln(
                        name='Regular Expression Denial of Service (ReDoS)',
                        severity='high',
                        category='Denial of Service',
                        description=(
                            f'The field "{target_field}" appears vulnerable to ReDoS. '
                            f'A crafted input caused the server to respond in '
                            f'{elapsed:.1f}s vs baseline {baseline_time:.1f}s. '
                            f'Payload type: {payload_info["name"]}.'
                        ),
                        impact='Denial of service via CPU exhaustion from regex backtracking',
                        remediation=(
                            'Replace vulnerable regex with atomic groups or possessive '
                            'quantifiers. Set regex execution timeouts. Use re2 or similar '
                            'linear-time regex engine.'
                        ),
                        cwe='CWE-1333',
                        cvss=7.5,
                        affected_url=action,
                        evidence=(
                            f'Field: {target_field}, Payload: {payload_info["name"]}, '
                            f'Response time: {elapsed:.1f}s (baseline: {baseline_time:.1f}s)'
                        ),
                    )
            except Exception:
                continue
        return None

    def _time_based_param_redos(self, url: str, param_name: str):
        """Test a URL parameter for ReDoS using time comparison."""
        base_url = re.sub(
            rf'([?&]){re.escape(param_name)}=[^&]*',
            rf'\g<1>{param_name}=normalvalue',
            url,
        )

        try:
            t0 = time.monotonic()
            self._make_request('GET', base_url)
            baseline_time = time.monotonic() - t0
        except Exception:
            return None

        for payload_info in REDOS_PAYLOADS[:3]:
            evil_url = re.sub(
                rf'([?&]){re.escape(param_name)}=[^&]*',
                rf'\g<1>{param_name}={payload_info["payload"]}',
                url,
            )

            try:
                t0 = time.monotonic()
                self._make_request('GET', evil_url)
                elapsed = time.monotonic() - t0

                if (elapsed > REDOS_TIME_THRESHOLD
                        and elapsed > baseline_time * REDOS_BASELINE_MULTIPLIER):
                    return self._build_vuln(
                        name='Regular Expression Denial of Service (ReDoS)',
                        severity='high',
                        category='Denial of Service',
                        description=(
                            f'The parameter "{param_name}" appears vulnerable to ReDoS. '
                            f'Response: {elapsed:.1f}s vs baseline {baseline_time:.1f}s.'
                        ),
                        impact='Denial of service via CPU exhaustion from regex backtracking',
                        remediation=(
                            'Use linear-time regex engines (re2). Set execution timeouts. '
                            'Avoid nested quantifiers in validation patterns.'
                        ),
                        cwe='CWE-1333',
                        cvss=7.5,
                        affected_url=evil_url,
                        evidence=(
                            f'Param: {param_name}, Payload: {payload_info["name"]}, '
                            f'Time: {elapsed:.1f}s (baseline: {baseline_time:.1f}s)'
                        ),
                    )
            except Exception:
                continue
        return None
