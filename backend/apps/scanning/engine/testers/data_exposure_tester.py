"""
DataExposureTester — Tests for sensitive data exposure.
OWASP A02:2021 — Cryptographic Failures.
"""
import re
import logging
from urllib.parse import urlparse, parse_qs
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

SENSITIVE_PATTERNS = {
    'Email Address': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'Credit Card (Visa)': r'\b4[0-9]{12}(?:[0-9]{3})?\b',
    'Credit Card (MC)': r'\b5[1-5][0-9]{14}\b',
    'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'Private Key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    'API Key Pattern': r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}',
    'JWT Token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
}

SENSITIVE_URL_PARAMS = [
    'password', 'passwd', 'pwd', 'pass', 'secret',
    'token', 'api_key', 'apikey', 'auth', 'session',
    'ssn', 'credit_card', 'cc', 'cvv',
]

BACKUP_EXTENSIONS = [
    '.bak', '.backup', '.old', '.orig', '.copy', '.save',
    '.sql', '.dump', '.tar.gz', '.zip', '.log',
]


class DataExposureTester(BaseTester):
    """Test for sensitive data exposure vulnerabilities."""

    TESTER_NAME = 'Data Exposure'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Check for HTTPS
        vuln = self._check_https(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for sensitive data in URLs
        vuln = self._check_sensitive_url_params(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for sensitive data in page source
        if depth in ('medium', 'deep'):
            vulns = self._check_sensitive_data_in_source(page)
            vulnerabilities.extend(vulns)

        # Check for exposed source code
        vuln = self._check_source_maps(page)
        if vuln:
            vulnerabilities.append(vuln)

        # Check for backup files
        if depth == 'deep':
            vulns = self._check_backup_files(page.url)
            vulnerabilities.extend(vulns)

        # Check cache control headers
        vuln = self._check_cache_headers(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_https(self, url):
        """Check if the site uses HTTPS."""
        if url.startswith('http://'):
            return self._build_vuln(
                name='Missing HTTPS Encryption',
                severity='high',
                category='Sensitive Data Exposure',
                description='The application is served over unencrypted HTTP instead of HTTPS.',
                impact='All data transmitted between the client and server can be intercepted, '
                      'including credentials, personal data, and session tokens.',
                remediation='Enable HTTPS with a valid TLS certificate. Redirect all HTTP to HTTPS. '
                           'Use HSTS headers to enforce secure connections.',
                cwe='CWE-319',
                cvss=7.5,
                affected_url=url,
                evidence='Site accessed over HTTP (unencrypted).',
            )
        return None

    def _check_sensitive_url_params(self, url):
        """Check for sensitive data in URL parameters."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params:
            if param.lower() in SENSITIVE_URL_PARAMS:
                return self._build_vuln(
                    name=f'Sensitive Data in URL: {param}',
                    severity='high',
                    category='Sensitive Data Exposure',
                    description=f'Sensitive parameter "{param}" is passed via URL query string.',
                    impact='URL parameters are logged in browser history, server logs, referrer headers, '
                          'and proxy logs, exposing sensitive data.',
                    remediation='Transmit sensitive data via POST body or HTTP headers, not URL parameters.',
                    cwe='CWE-598',
                    cvss=6.5,
                    affected_url=url,
                    evidence=f'Sensitive parameter in URL: {param}',
                )
        return None

    def _check_sensitive_data_in_source(self, page):
        """Check for sensitive data patterns in HTML source."""
        vulnerabilities = []
        body = page.body

        # Only check for high-confidence patterns
        for name, pattern in SENSITIVE_PATTERNS.items():
            if name == 'Email Address':
                continue  # Too many false positives
            matches = re.findall(pattern, body)
            if matches:
                vulnerabilities.append(self._build_vuln(
                    name=f'Sensitive Data Found: {name}',
                    severity='high' if 'Key' in name or 'Private' in name else 'medium',
                    category='Sensitive Data Exposure',
                    description=f'{name} pattern detected in page source.',
                    impact='Exposed sensitive data can be harvested by attackers for identity theft, '
                          'unauthorized access, or financial fraud.',
                    remediation='Remove sensitive data from client-side code. Use server-side '
                               'rendering for sensitive information. Mask or truncate displayed data.',
                    cwe='CWE-200',
                    cvss=6.5 if 'Key' in name else 4.3,
                    affected_url=page.url,
                    evidence=f'Pattern matches found: {len(matches)} instance(s) of {name}.',
                ))

        # Check for HTML comments containing sensitive info
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        for comment in comments:
            sensitive_keywords = ['password', 'secret', 'key', 'token', 'todo', 'fixme', 'hack', 'credential']
            if any(kw in comment.lower() for kw in sensitive_keywords):
                vulnerabilities.append(self._build_vuln(
                    name='Sensitive Information in HTML Comments',
                    severity='low',
                    category='Sensitive Data Exposure',
                    description='HTML comments contain potentially sensitive information.',
                    impact='Developers may leave notes, credentials, or internal details in comments.',
                    remediation='Remove all HTML comments from production code during the build process.',
                    cwe='CWE-615',
                    cvss=3.7,
                    affected_url=page.url,
                    evidence=f'Comment excerpt: {comment[:100].strip()}...',
                ))
                break  # Report once

        return vulnerabilities

    def _check_source_maps(self, page):
        """Check for exposed source maps."""
        body = page.body
        if '//# sourceMappingURL=' in body:
            return self._build_vuln(
                name='Source Map File Exposed',
                severity='low',
                category='Sensitive Data Exposure',
                description='The application includes source map references, exposing original source code.',
                impact='Source maps reveal unminified source code, making it easier to find vulnerabilities.',
                remediation='Remove source maps from production builds or restrict access via server configuration.',
                cwe='CWE-540',
                cvss=3.7,
                affected_url=page.url,
                evidence='sourceMappingURL directive found in page source.',
            )
        return None

    def _check_backup_files(self, url):
        """Check for exposed backup files."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = f'{parsed.scheme}://{parsed.netloc}'
        vulnerabilities = []

        # Try common backup paths
        for ext in BACKUP_EXTENSIONS[:5]:
            test_url = f'{base}/backup{ext}'
            response = self._make_request('GET', test_url)
            if response and response.status_code == 200 and len(response.text) > 100:
                vulnerabilities.append(self._build_vuln(
                    name=f'Backup File Exposed: backup{ext}',
                    severity='high',
                    category='Sensitive Data Exposure',
                    description=f'A backup file (backup{ext}) is publicly accessible.',
                    impact='Backup files may contain source code, database dumps, or configuration with credentials.',
                    remediation='Remove backup files from web-accessible directories. '
                               'Use proper access controls for sensitive files.',
                    cwe='CWE-530',
                    cvss=7.5,
                    affected_url=test_url,
                    evidence=f'Accessible backup file: {test_url} ({len(response.text)} bytes)',
                ))
                break  # Report once

        return vulnerabilities

    def _check_cache_headers(self, url):
        """Check for missing cache control headers on sensitive pages."""
        response = self._make_request('GET', url)
        if not response:
            return None

        cache_control = response.headers.get('Cache-Control', '')
        pragma = response.headers.get('Pragma', '')

        if not cache_control and not pragma:
            return self._build_vuln(
                name='Missing Cache-Control Headers',
                severity='low',
                category='Sensitive Data Exposure',
                description='The response does not include Cache-Control headers.',
                impact='Sensitive data may be cached by browsers or proxies, '
                      'accessible to other users of shared computers.',
                remediation='Set Cache-Control: no-store, no-cache for pages with sensitive data. '
                           'Add Pragma: no-cache for HTTP/1.0 compatibility.',
                cwe='CWE-525',
                cvss=3.1,
                affected_url=url,
                evidence='No Cache-Control or Pragma headers found.',
            )
        return None
