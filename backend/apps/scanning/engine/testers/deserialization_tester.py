"""
DeserializationTester — Insecure Deserialization detection.
OWASP A08:2021 — Software and Data Integrity Failures.

Tests for: Java serialization markers, Python pickle, PHP unserialize,
.NET ViewState, Node.js eval, and deserialization error disclosure.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Serialized data markers
JAVA_SERIAL_MAGIC = b'\xac\xed\x00\x05'
BASE64_JAVA_PREFIX = 'rO0AB'  # base64 of Java magic bytes

DESERIALIZATION_PAYLOADS = {
    'java': [
        'rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtmTfIbQFVcEAgFaAAV2YWx1ZXhwAQ==',
        'rO0ABXNyAA5qYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0',
    ],
    'python': [
        "cos\nsystem\n(S'echo'\ntR.",           # pickle
        "c__builtin__\neval\n(S'1+1'\ntR.",      # pickle eval
    ],
    'php': [
        'O:8:"stdClass":0:{}',
        'a:1:{s:4:"test";s:4:"data";}',
        'O:3:"Foo":1:{s:3:"bar";s:6:"system";}',
    ],
    'dotnet': [
        '/wEPDwUJOTU4MjE0',  # ViewState prefix
    ],
}

# Error patterns indicating deserialization processing
DESER_ERROR_PATTERNS = [
    r'java\.io\.ObjectInputStream',
    r'java\.io\.InvalidClassException',
    r'ClassNotFoundException',
    r'java\.io\.StreamCorruptedException',
    r'UnpicklingError',
    r'pickle\.loads',
    r'unserialize\(\)',
    r'__PHP_Incomplete_Class',
    r'ViewState\s+MAC\s+validation',
    r'System\.Runtime\.Serialization',
    r'ObjectDisposedException',
    r'BinaryFormatter',
    r'InvalidCastException.*deserializ',
]


class DeserializationTester(BaseTester):
    """Test for insecure deserialization vulnerabilities."""

    TESTER_NAME = 'Deserialization'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Check for serialized data in cookies
        vulns = self._check_cookies(page)
        vulnerabilities.extend(vulns)

        # Check for serialized data in hidden form fields
        vulns = self._check_hidden_fields(page)
        vulnerabilities.extend(vulns)

        # Test parameter-based deserialization (medium/deep)
        if depth in ('medium', 'deep'):
            vulns = self._test_param_deserialization(page)
            vulnerabilities.extend(vulns)

        # Check for ViewState (ASP.NET)
        vuln = self._check_viewstate(page)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_cookies(self, page):
        """Check cookies for serialized data indicators."""
        vulns = []
        response = self._make_request('GET', page.url)
        if not response:
            return vulns

        for name, value in response.cookies.items():
            tech = self._detect_serialization(value)
            if tech:
                vulns.append(self._build_vuln(
                    name=f'Serialized Data in Cookie: {name} ({tech})',
                    severity='high',
                    category='Insecure Deserialization',
                    description=f'The cookie "{name}" contains {tech} serialized data. '
                               f'If the server deserializes this without validation, '
                               f'it can lead to remote code execution.',
                    impact='Attackers can craft malicious serialized payloads to execute '
                          'arbitrary code on the server.',
                    remediation='Avoid deserializing untrusted data. Use digital signatures '
                               'to verify serialized data integrity. Prefer JSON over native serialization.',
                    cwe='CWE-502',
                    cvss=8.1,
                    affected_url=page.url,
                    evidence=f'Cookie: {name}\nTechnology: {tech}\nValue prefix: {value[:50]}...',
                ))
        return vulns

    def _check_hidden_fields(self, page):
        """Check hidden form fields for serialized data."""
        vulns = []
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type != 'hidden' or not inp.value:
                    continue
                tech = self._detect_serialization(inp.value)
                if tech:
                    vulns.append(self._build_vuln(
                        name=f'Serialized Data in Hidden Field: {inp.name} ({tech})',
                        severity='high',
                        category='Insecure Deserialization',
                        description=f'The hidden field "{inp.name}" contains {tech} serialized data.',
                        impact='Attackers can modify serialized data client-side to exploit '
                              'server-side deserialization.',
                        remediation='Sign and validate serialized data. Never trust client-supplied '
                                   'serialized objects.',
                        cwe='CWE-502',
                        cvss=8.1,
                        affected_url=page.url,
                        evidence=f'Field: {inp.name}\nTechnology: {tech}\nValue prefix: {inp.value[:50]}...',
                    ))
        return vulns

    def _test_param_deserialization(self, page):
        """Test parameters with serialized payloads to trigger errors."""
        vulns = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        for param_name, param_value in page.parameters.items():
            for tech, payloads in DESERIALIZATION_PAYLOADS.items():
                for payload in payloads[:1]:
                    parsed = urlparse(page.url)
                    params = parse_qs(parsed.query)
                    params[param_name] = payload
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(params, doseq=True), '',
                    ))

                    response = self._make_request('GET', test_url)
                    if response and self._has_deser_error(response.text):
                        vulns.append(self._build_vuln(
                            name=f'Deserialization Error Disclosure: {param_name}',
                            severity='high',
                            category='Insecure Deserialization',
                            description=f'Injecting {tech} serialized data into "{param_name}" '
                                       f'triggered deserialization error messages, confirming '
                                       f'that user input is being deserialized.',
                            impact='Confirmed deserialization of user input can lead to RCE.',
                            remediation='Remove deserialization of user-supplied data. '
                                       'Use safe alternatives like JSON.',
                            cwe='CWE-502',
                            cvss=9.8,
                            affected_url=page.url,
                            evidence=f'Parameter: {param_name}\nPayload: {tech} serialized data\n'
                                    f'Deserialization error message returned.',
                        ))
                        break
        return vulns

    def _check_viewstate(self, page):
        """Check for ASP.NET ViewState without MAC validation."""
        body = page.body or ''
        viewstate_match = re.search(
            r'<input[^>]*name\s*=\s*"__VIEWSTATE"[^>]*value\s*=\s*"([^"]+)"',
            body, re.IGNORECASE,
        )
        if not viewstate_match:
            return None

        value = viewstate_match.group(1)
        # ViewState without MAC starts with /wEP (no MAC) vs signed ones
        if value.startswith('/wEP'):
            return self._build_vuln(
                name='ASP.NET ViewState Without MAC Validation',
                severity='critical',
                category='Insecure Deserialization',
                description='The ASP.NET ViewState field lacks MAC validation, '
                           'allowing tampering and potential remote code execution '
                           'via deserialization attacks.',
                impact='Attackers can modify ViewState to inject malicious serialized objects, '
                      'leading to RCE on the server.',
                remediation='Enable ViewState MAC validation: <pages enableViewStateMac="true" /> '
                           'in web.config. Use ASP.NET 4.5+ with automatic MAC validation.',
                cwe='CWE-502',
                cvss=9.8,
                affected_url=page.url,
                evidence=f'ViewState value prefix: {value[:50]}...\nNo MAC signature detected.',
            )
        return None

    def _detect_serialization(self, value):
        """Detect serialization technology in a string value."""
        if not value:
            return None
        if value.startswith(BASE64_JAVA_PREFIX):
            return 'Java'
        if value.startswith('/wEP') or value.startswith('/wEY'):
            return '.NET ViewState'
        if re.match(r'^[OaCis]:\d+:', value):
            return 'PHP'
        if re.match(r'^gASV|^ccopy_reg', value):
            return 'Python (pickle)'
        return None

    def _has_deser_error(self, body):
        """Check for deserialization error patterns."""
        if not body:
            return False
        for pattern in DESER_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False
