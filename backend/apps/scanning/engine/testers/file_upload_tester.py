"""
FileUploadTester — File Upload vulnerability detection.
OWASP A04:2021 — Insecure Design, A03:2021 — Injection.

Tests for: unrestricted file upload, extension bypass, content-type bypass,
double extension, null byte extension, polyglot files, and path traversal in filenames.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Malicious file content for testing
PHP_WEBSHELL = b'<?php echo "FILEUPLOAD_TEST_SUCCESS"; ?>'
JSP_WEBSHELL = b'<% out.println("FILEUPLOAD_TEST_SUCCESS"); %>'
ASPX_WEBSHELL = b'<%@ Page Language="C#" %><% Response.Write("FILEUPLOAD_TEST_SUCCESS"); %>'
SVG_XSS = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>'
HTML_XSS = b'<html><body><script>alert("XSS")</script></body></html>'

# Upload test payloads: (filename, content, content_type, description)
UPLOAD_PAYLOADS = [
    # Extension bypass
    ('test.php', PHP_WEBSHELL, 'application/x-php', 'PHP webshell'),
    ('test.php5', PHP_WEBSHELL, 'application/x-php', 'PHP5 extension'),
    ('test.phtml', PHP_WEBSHELL, 'application/x-php', 'PHTML extension'),
    ('test.php.jpg', PHP_WEBSHELL, 'image/jpeg', 'Double extension (PHP)'),
    ('test.jsp', JSP_WEBSHELL, 'application/x-jsp', 'JSP webshell'),
    ('test.aspx', ASPX_WEBSHELL, 'application/x-aspx', 'ASPX webshell'),

    # Content-type bypass
    ('test.php', PHP_WEBSHELL, 'image/jpeg', 'PHP with image content-type'),
    ('test.php', PHP_WEBSHELL, 'image/png', 'PHP with PNG content-type'),

    # Special extensions
    ('test.svg', SVG_XSS, 'image/svg+xml', 'SVG with XSS'),
    ('test.html', HTML_XSS, 'text/html', 'HTML with XSS'),
    ('.htaccess', b'AddType application/x-httpd-php .txt', 'text/plain', '.htaccess override'),

    # Null byte
    ('test.php%00.jpg', PHP_WEBSHELL, 'image/jpeg', 'Null byte extension'),
    ('test.php\\x00.jpg', PHP_WEBSHELL, 'image/jpeg', 'Null byte (literal)'),
]

# Path traversal filenames
TRAVERSAL_FILENAMES = [
    '../../../test.php',
    '..\\..\\..\\test.php',
    '....//....//test.php',
    'test.php/../../../etc/passwd',
]


class FileUploadTester(BaseTester):
    """Test for file upload vulnerabilities."""

    TESTER_NAME = 'File Upload'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        for form in page.forms:
            file_input = self._find_file_input(form)
            if not file_input:
                continue

            # Test unrestricted upload
            payloads = UPLOAD_PAYLOADS[:4] if depth == 'shallow' else UPLOAD_PAYLOADS
            for filename, content, content_type, desc in payloads:
                vuln = self._test_upload(form, file_input, page.url,
                                         filename, content, content_type, desc)
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # One finding per form is sufficient for basic uploads

            # Test path traversal in filename (medium/deep)
            if depth in ('medium', 'deep'):
                vuln = self._test_filename_traversal(form, file_input, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

            # Test oversized file (deep)
            if depth == 'deep':
                vuln = self._test_oversized_upload(form, file_input, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

            # Check for client-side-only validation
            vuln = self._check_client_side_validation(form, file_input, page)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _find_file_input(self, form):
        """Find file input field in form."""
        for inp in form.inputs:
            if inp.input_type == 'file':
                return inp
        return None

    def _test_upload(self, form, file_input, page_url, filename, content, content_type, desc):
        """Test a specific file upload payload."""
        target_url = form.action or page_url

        data = {}
        for fi in form.inputs:
            if fi.input_type != 'file' and fi.name:
                data[fi.name] = fi.value or 'test'

        files = {file_input.name: (filename, content, content_type)}

        try:
            response = self._make_request('POST', target_url, files=files, data=data)
        except Exception:
            return None

        if not response:
            return None

        # Check if upload was accepted
        if response.status_code in (200, 201, 302):
            body = response.text.lower()
            # Check for success indicators
            success_indicators = ['uploaded', 'success', 'saved', 'created',
                                  'file uploaded', 'upload complete']
            error_indicators = ['invalid', 'not allowed', 'rejected', 'forbidden',
                                'extension', 'type not', 'denied']

            is_success = any(k in body for k in success_indicators)
            is_error = any(k in body for k in error_indicators)

            if is_success and not is_error:
                # Determine severity based on what was uploaded
                if any(k in filename for k in ('.php', '.jsp', '.aspx', '.htaccess')):
                    severity = 'critical'
                    cvss = 9.8
                elif any(k in filename for k in ('.svg', '.html')):
                    severity = 'high'
                    cvss = 7.5
                else:
                    severity = 'medium'
                    cvss = 5.3

                return self._build_vuln(
                    name=f'Unrestricted File Upload: {desc}',
                    severity=severity,
                    category='File Upload',
                    description=f'The server accepted a potentially malicious file upload: "{filename}" '
                               f'with content-type "{content_type}" ({desc}).',
                    impact='Uploading executable files (PHP, JSP, ASPX) can lead to remote code execution. '
                          'SVG/HTML uploads can enable stored XSS attacks.',
                    remediation='Validate file extensions against an allowlist. '
                               'Verify file content (magic bytes), not just content-type. '
                               'Store uploads outside web root. Rename files with random names. '
                               'Use a CDN or separate domain for serving user uploads.',
                    cwe='CWE-434',
                    cvss=cvss,
                    affected_url=target_url,
                    evidence=f'File: {filename}\nContent-Type: {content_type}\nDescription: {desc}\n'
                            f'Upload appears to have been accepted.',
                )
        return None

    def _test_filename_traversal(self, form, file_input, page_url):
        """Test for path traversal in uploaded filenames."""
        target_url = form.action or page_url

        for filename in TRAVERSAL_FILENAMES[:2]:
            data = {}
            for fi in form.inputs:
                if fi.input_type != 'file' and fi.name:
                    data[fi.name] = fi.value or 'test'

            files = {file_input.name: (filename, b'TRAVERSAL_TEST', 'text/plain')}

            try:
                response = self._make_request('POST', target_url, files=files, data=data)
            except Exception:
                continue

            if response and response.status_code in (200, 201, 302):
                body = response.text.lower()
                if any(k in body for k in ('uploaded', 'success', 'saved')):
                    return self._build_vuln(
                        name='Path Traversal in Upload Filename',
                        severity='critical',
                        category='File Upload',
                        description=f'The server accepted a file upload with a path traversal '
                                   f'filename: "{filename}", potentially writing files outside '
                                   f'the intended upload directory.',
                        impact='Attackers can overwrite critical files or place executable files '
                              'in web-accessible directories.',
                        remediation='Sanitize filenames: remove path separators (/, \\), encoded sequences. '
                                   'Use a random generated filename for stored files.',
                        cwe='CWE-22',
                        cvss=9.1,
                        affected_url=target_url,
                        evidence=f'Traversal filename: {filename} was accepted.',
                    )
        return None

    def _test_oversized_upload(self, form, file_input, page_url):
        """Test if the server accepts oversized file uploads."""
        target_url = form.action or page_url

        # Try a 10MB file
        large_content = b'A' * (10 * 1024 * 1024)

        data = {}
        for fi in form.inputs:
            if fi.input_type != 'file' and fi.name:
                data[fi.name] = fi.value or 'test'

        files = {file_input.name: ('large_test.txt', large_content, 'text/plain')}

        try:
            response = self._make_request('POST', target_url, files=files, data=data, timeout=30)
        except Exception:
            return None

        if response and response.status_code in (200, 201, 302):
            return self._build_vuln(
                name='No File Size Limit',
                severity='low',
                category='File Upload',
                description='The server accepted a 10MB file upload without size restrictions.',
                impact='Attackers can exhaust disk space or cause denial of service '
                      'by uploading very large files.',
                remediation='Implement file size limits both client-side and server-side. '
                           'Set MAX_UPLOAD_SIZE in your web framework configuration.',
                cwe='CWE-770',
                cvss=3.7,
                affected_url=target_url,
                evidence='10MB file upload accepted.',
            )
        return None

    def _check_client_side_validation(self, form, file_input, page):
        """Check if file upload validation is only client-side."""
        body = page.body or ''

        # Look for accept attribute (client-side only)
        accept_pattern = re.search(
            rf'<input[^>]*name\s*=\s*["\'{re.escape(file_input.name or "")}"\'][^>]*accept\s*=\s*"([^"]+)"',
            body, re.IGNORECASE,
        )

        # Look for JavaScript validation
        js_validation = re.search(
            r'(\.files\[0\]\.type|\.accept|allowedExtensions|validFileTypes)',
            body, re.IGNORECASE,
        )

        if (accept_pattern or js_validation) and not self._has_server_validation_hints(body):
            return self._build_vuln(
                name='Client-Side Only File Validation',
                severity='medium',
                category='File Upload',
                description='The file upload form appears to rely solely on client-side validation '
                           '(accept attribute and/or JavaScript checks). These can be easily bypassed.',
                impact='Attackers can bypass client-side restrictions by modifying the request directly.',
                remediation='Always validate file type, size, and content server-side. '
                           'Client-side validation is for UX only, not security.',
                cwe='CWE-434',
                cvss=5.3,
                affected_url=page.url,
                evidence='Client-side file validation detected without visible server-side validation.',
            )
        return None

    def _has_server_validation_hints(self, body):
        """Check if there are hints of server-side validation."""
        server_hints = ['server-side', 'validated on server', 'backend validation']
        return any(h in body.lower() for h in server_hints)
