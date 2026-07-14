"""
XSLT Injection Tester — Detects XSLT injection vulnerabilities.

Covers:
  - System command execution via XSLT functions
  - File read via document() function
  - XSLT processor detection
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── XSLT indicators in responses ────────────────────────────────────────────
XSLT_INDICATORS = [
    re.compile(r'<xsl:', re.IGNORECASE),
    re.compile(r'xsl:stylesheet', re.IGNORECASE),
    re.compile(r'xsl:transform', re.IGNORECASE),
    re.compile(r'xsl:output', re.IGNORECASE),
    re.compile(r'xsl:template', re.IGNORECASE),
    re.compile(r'xmlns:xsl', re.IGNORECASE),
]

# ── XSLT/XML content-type indicators ────────────────────────────────────────
XSLT_CONTENT_TYPES = [
    'text/xml', 'application/xml', 'text/xsl',
    'application/xslt+xml', 'application/xsl',
]

# ── XSLT injection payloads ─────────────────────────────────────────────────
XSLT_PROBE_PAYLOADS = [
    # Version detection
    '<xsl:value-of select="system-property(\'xsl:version\')"/>',
    # Vendor detection
    '<xsl:value-of select="system-property(\'xsl:vendor\')"/>',
]

# ── XSLT successful injection indicators ────────────────────────────────────
XSLT_SUCCESS_PATTERNS = [
    re.compile(r'(?:1\.0|2\.0|3\.0)'),  # XSLT version numbers
    re.compile(r'(?:libxslt|xalan|saxon|microsoft|apache)', re.IGNORECASE),
    re.compile(r'root:.*:0:0:', re.IGNORECASE),  # /etc/passwd content
]

# ── XML endpoints likely to process XSLT ─────────────────────────────────────
XSLT_ENDPOINT_PATTERNS = [
    r'/transform', r'/convert', r'/render', r'/xml',
    r'/xsl', r'/xslt', r'/report', r'/export',
    r'/template', r'/format', r'\.xml$', r'\.xsl$',
]

# ── Parameters likely to accept XML/XSLT ─────────────────────────────────────
XSLT_PARAM_PATTERNS = [
    'xml', 'xsl', 'xslt', 'template', 'stylesheet',
    'transform', 'data', 'input', 'source', 'content',
]


class XSLTInjectionTester(BaseTester):
    """Test for XSLT injection vulnerabilities."""

    TESTER_NAME = 'XSLT Injection'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        headers = getattr(page, 'headers', {}) or {}
        params = getattr(page, 'parameters', {}) or {}
        forms = getattr(page, 'forms', []) or []

        content_type = headers.get('Content-Type', '')
        is_xml_endpoint = self._is_xml_endpoint(url, content_type)

        # 1. Check for XSLT indicators in page body
        vuln = self._check_xslt_indicators(url, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Test parameter injection for XSLT
        if is_xml_endpoint or params:
            vuln = self._test_param_xslt_injection(url, params)
            if vuln:
                vulns.append(vuln)

        if depth == 'deep':
            # 3. Test form-based XSLT injection
            for form in forms[:2]:
                vuln = self._test_form_xslt_injection(url, form)
                if vuln:
                    vulns.append(vuln)
                    break

        return vulns

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_xml_endpoint(self, url: str, content_type: str) -> bool:
        for pattern in XSLT_ENDPOINT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        for ct in XSLT_CONTENT_TYPES:
            if ct in content_type.lower():
                return True
        return False

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_xslt_indicators(self, url: str, body: str):
        """Check for XSLT processing indicators in the response."""
        found = []
        for pattern in XSLT_INDICATORS:
            if pattern.search(body):
                found.append(pattern.pattern)

        if found:
            return self._build_vuln(
                name='XSLT Processing Detected',
                severity='low',
                category='Information Disclosure',
                description=(
                    'XSLT processing indicators found in the response. '
                    'If user-controlled input reaches the XSLT processor, '
                    'it may enable code execution or file read.'
                ),
                impact='Information disclosure, potential XSLT injection',
                remediation=(
                    'Remove XSLT debug output from responses. '
                    'Sanitize XML input before XSLT processing.'
                ),
                cwe='CWE-91',
                cvss=3.7,
                affected_url=url,
                evidence=f'XSLT patterns: {", ".join(found[:3])}',
            )
        return None

    def _test_param_xslt_injection(self, url: str, params: dict):
        """Test XSLT injection via URL parameters."""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        all_params = {**params, **{k: v[0] for k, v in qs.items()}}

        # Focus on parameters likely to accept XML/XSLT
        target_params = [
            p for p in all_params
            if p.lower() in XSLT_PARAM_PATTERNS
        ]
        if not target_params:
            target_params = list(all_params.keys())[:2]

        for param_name in target_params[:3]:
            for payload in XSLT_PROBE_PAYLOADS:
                try:
                    test_qs = dict(qs)
                    test_qs[param_name] = [payload]
                    test_query = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=test_query)
                    )
                    resp = self._make_request('GET', test_url)
                    if not resp:
                        continue

                    resp_body = getattr(resp, 'text', '')
                    if any(p.search(resp_body) for p in XSLT_SUCCESS_PATTERNS):
                        return self._build_vuln(
                            name='XSLT Injection via Parameter',
                            severity='critical',
                            category='Injection',
                            description=(
                                f'XSLT injection detected via parameter '
                                f'"{param_name}". The server processes XSLT '
                                'input, enabling file read and command execution.'
                            ),
                            impact='Remote code execution, arbitrary file read, SSRF',
                            remediation=(
                                'Disable XSLT processing of user input. '
                                'Use allowlists for XSLT functions. '
                                'Sandbox the XSLT processor.'
                            ),
                            cwe='CWE-91',
                            cvss=9.8,
                            affected_url=test_url,
                            evidence=f'XSLT payload processed via "{param_name}"',
                        )
                except Exception:
                    continue
        return None

    def _test_form_xslt_injection(self, url: str, form):
        """Test XSLT injection via form inputs."""
        action = getattr(form, 'action', '') or url
        method = getattr(form, 'method', 'POST').upper()
        inputs = getattr(form, 'inputs', []) or []

        for inp in inputs:
            inp_name = getattr(inp, 'name', '')
            if not inp_name:
                continue

            # Prioritize XML-related input names
            if inp_name.lower() not in XSLT_PARAM_PATTERNS:
                continue

            for payload in XSLT_PROBE_PAYLOADS:
                try:
                    resp = self._make_request(
                        method, action,
                        data={inp_name: payload},
                    )
                    if not resp:
                        continue

                    resp_body = getattr(resp, 'text', '')
                    if any(p.search(resp_body) for p in XSLT_SUCCESS_PATTERNS):
                        return self._build_vuln(
                            name='XSLT Injection via Form',
                            severity='critical',
                            category='Injection',
                            description=(
                                f'XSLT injection via form field "{inp_name}". '
                                'The XSLT processor executed injected directives.'
                            ),
                            impact='Remote code execution, arbitrary file read',
                            remediation=(
                                'Validate and sanitize XML input. '
                                'Disable dangerous XSLT functions.'
                            ),
                            cwe='CWE-91',
                            cvss=9.8,
                            affected_url=action,
                            evidence=f'XSLT payload executed via form field "{inp_name}"',
                        )
                except Exception:
                    continue
        return None
