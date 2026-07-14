"""
MisconfigTester — Tests for security misconfigurations.
OWASP A05:2021 — Security Misconfiguration.

Comprehensive checks: security headers, directory listing, HTTP methods,
sensitive paths, verbose errors, server banners, CSP analysis,
cookie flags, HSTS, and technology fingerprinting.
"""
import re
import logging
from urllib.parse import urljoin, urlparse
from .base_tester import BaseTester
from ..payloads.sensitive_paths import ALL_PATHS

logger = logging.getLogger(__name__)

DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']

# Required security headers
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'missing_severity': 'medium',
        'missing_cvss': 4.3,
        'description': 'HTTP Strict Transport Security (HSTS)',
        'remediation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    'Content-Security-Policy': {
        'missing_severity': 'medium',
        'missing_cvss': 4.3,
        'description': 'Content Security Policy (CSP)',
        'remediation': "Add a Content-Security-Policy header with restrictive directives: "
                      "default-src 'self'; script-src 'self'",
    },
    'X-Content-Type-Options': {
        'missing_severity': 'low',
        'missing_cvss': 3.1,
        'description': 'X-Content-Type-Options prevents MIME type sniffing',
        'remediation': 'Add X-Content-Type-Options: nosniff',
    },
    'X-Frame-Options': {
        'missing_severity': 'medium',
        'missing_cvss': 4.3,
        'description': 'X-Frame-Options prevents clickjacking',
        'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN',
    },
    'Referrer-Policy': {
        'missing_severity': 'low',
        'missing_cvss': 2.0,
        'description': 'Referrer-Policy controls information leakage via Referer header',
        'remediation': 'Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer',
    },
    'Permissions-Policy': {
        'missing_severity': 'low',
        'missing_cvss': 2.0,
        'description': 'Permissions-Policy controls browser features',
        'remediation': 'Add Permissions-Policy: camera=(), microphone=(), geolocation=()',
    },
}

# Server banner patterns that reveal technology
SERVER_BANNERS = {
    r'Apache/(\d+\.\d+)': 'Apache',
    r'nginx/(\d+\.\d+)': 'Nginx',
    r'Microsoft-IIS/(\d+\.\d+)': 'IIS',
    r'PHP/(\d+\.\d+)': 'PHP',
    r'Express': 'Express.js',
    r'Kestrel': 'ASP.NET Kestrel',
    r'Werkzeug/(\d+\.\d+)': 'Werkzeug (Python)',
    r'gunicorn': 'Gunicorn (Python)',
    r'Jetty': 'Jetty (Java)',
    r'Tomcat': 'Apache Tomcat',
}


class MisconfigTester(BaseTester):
    """Test for server and application misconfigurations."""

    TESTER_NAME = 'Misconfiguration'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # 1. Check security headers
        vulns = self._check_security_headers(page)
        vulnerabilities.extend(vulns)

        # 2. Check server banner information disclosure
        vuln = self._check_server_banner(page)
        if vuln:
            vulnerabilities.append(vuln)

        # 3. Test directory listing
        vuln = self._test_directory_listing(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # 4. Test dangerous HTTP methods
        vuln = self._test_http_methods(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # 5. Test exposed sensitive files/paths
        if depth in ('medium', 'deep'):
            max_paths = 15 if depth == 'medium' else 40
            vulns = self._test_sensitive_paths(page.url, ALL_PATHS[:max_paths])
            vulnerabilities.extend(vulns)

        # 6. Test verbose error pages
        vulns = self._test_verbose_errors(page.url)
        vulnerabilities.extend(vulns)

        # 7. Analyze CSP policy (medium/deep)
        if depth in ('medium', 'deep'):
            vulns = self._analyze_csp(page)
            vulnerabilities.extend(vulns)

        # 8. Check HSTS configuration (deep)
        if depth == 'deep':
            vuln = self._check_hsts_config(page)
            if vuln:
                vulnerabilities.append(vuln)

        # 9. Check for information in HTML comments (deep)
        if depth == 'deep':
            vuln = self._check_html_comments(page)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    # ----- Security Headers -----
    def _check_security_headers(self, page) -> list:
        """Check for missing or misconfigured security headers."""
        vulnerabilities = []

        try:
            response = self._make_request('GET', page.url)
        except Exception:
            return vulnerabilities

        if not response:
            return vulnerabilities

        missing = []
        for header_name, config in SECURITY_HEADERS.items():
            value = response.headers.get(header_name, '')
            if not value:
                missing.append((header_name, config))

        if missing:
            header_names = [h[0] for h in missing]
            max_severity = max(
                (h[1]['missing_severity'] for h in missing),
                key=lambda s: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(s, 0),
            )
            max_cvss = max(h[1]['missing_cvss'] for h in missing)
            remediation_list = '\n'.join(f'  - {h[1]["remediation"]}' for h in missing)

            vulnerabilities.append(self._build_vuln(
                name=f'Missing Security Headers ({len(missing)})',
                severity=max_severity,
                category='Security Misconfiguration',
                description=f'The following security headers are missing: {", ".join(header_names)}.',
                impact='Missing security headers leave the application vulnerable to clickjacking, '
                      'MIME-type confusion, XSS, and protocol downgrade attacks.',
                remediation=f'Add the following headers:\n{remediation_list}',
                cwe='CWE-693',
                cvss=max_cvss,
                affected_url=page.url,
                evidence=f'Missing headers: {", ".join(header_names)}',
            ))

        return vulnerabilities

    # ----- Server Banner -----
    def _check_server_banner(self, page) -> object:
        """Check for server version disclosure."""
        try:
            response = self._make_request('GET', page.url)
        except Exception:
            return None

        if not response:
            return None

        server = response.headers.get('Server', '')
        x_powered = response.headers.get('X-Powered-By', '')
        x_aspnet = response.headers.get('X-AspNet-Version', '')

        disclosed = []
        if server:
            disclosed.append(f'Server: {server}')
        if x_powered:
            disclosed.append(f'X-Powered-By: {x_powered}')
        if x_aspnet:
            disclosed.append(f'X-AspNet-Version: {x_aspnet}')

        if not disclosed:
            return None

        # Check if version numbers are exposed
        has_version = bool(re.search(r'\d+\.\d+', ' '.join(disclosed)))

        severity = 'low' if has_version else 'info'
        cvss = 2.0 if has_version else 0.0

        return self._build_vuln(
            name='Server Technology Disclosure',
            severity=severity,
            category='Security Misconfiguration',
            description=f'The server discloses technology details: {"; ".join(disclosed)}.'
                       f'{" Version numbers are exposed, aiding targeted attacks." if has_version else ""}',
            impact='Knowing the server software and version helps attackers find known '
                  'vulnerabilities and craft targeted exploits.',
            remediation='Remove or obfuscate the Server, X-Powered-By, and X-AspNet-Version '
                       'headers. Configure your web server to suppress version information.',
            cwe='CWE-200',
            cvss=cvss,
            affected_url=page.url,
            evidence='\n'.join(disclosed),
        )

    # ----- Directory Listing -----
    def _test_directory_listing(self, url):
        """Check if directory listing is enabled."""
        parsed = urlparse(url)
        for path in ['/', '/images/', '/css/', '/js/', '/assets/', '/static/', '/uploads/', '/media/']:
            test_url = f'{parsed.scheme}://{parsed.netloc}{path}'
            try:
                response = self._make_request('GET', test_url)
            except Exception:
                continue
            if response and response.status_code == 200:
                indicators = [
                    '<title>Index of', 'Directory listing for',
                    '<title>Directory Listing', 'Parent Directory',
                    '[To Parent Directory]', '<h1>Index of',
                ]
                if any(ind in response.text for ind in indicators):
                    return self._build_vuln(
                        name='Directory Listing Enabled',
                        severity='medium',
                        category='Security Misconfiguration',
                        description=f'Directory listing is enabled at {test_url}, exposing file structure.',
                        impact='Attackers can view all files in the directory, potentially discovering '
                              'sensitive files, backup files, or configuration data.',
                        remediation='Disable directory listing in web server configuration. '
                                   'Apache: Options -Indexes. Nginx: autoindex off.',
                        cwe='CWE-548',
                        cvss=5.3,
                        affected_url=test_url,
                        evidence='Directory listing page detected.',
                    )
        return None

    # ----- HTTP Methods -----
    def _test_http_methods(self, url):
        """Check for dangerous HTTP methods."""
        try:
            response = self._make_request('OPTIONS', url)
        except Exception:
            return None

        if not response:
            return None

        allow = response.headers.get('Allow', '')
        enabled = [m for m in DANGEROUS_METHODS if m in allow.upper()]

        # Also test TRACE directly
        try:
            trace_resp = self._make_request('TRACE', url)
            if trace_resp and trace_resp.status_code == 200:
                if 'TRACE' not in enabled:
                    enabled.append('TRACE')
        except Exception:
            pass

        if enabled:
            return self._build_vuln(
                name='Dangerous HTTP Methods Enabled',
                severity='medium',
                category='Security Misconfiguration',
                description=f'The server allows dangerous HTTP methods: {", ".join(enabled)}.',
                impact='TRACE can be used for Cross-Site Tracing (XST) attacks. '
                      'PUT/DELETE may allow unauthorized file manipulation.',
                remediation='Disable unnecessary HTTP methods. Only allow GET, POST, HEAD as needed.',
                cwe='CWE-749',
                cvss=4.3,
                affected_url=url,
                evidence=f'Enabled methods: {allow or ", ".join(enabled)}',
            )
        return None

    # ----- Sensitive Paths -----
    def _test_sensitive_paths(self, url, paths):
        """Check for exposed sensitive files and admin interfaces."""
        parsed = urlparse(url)
        base = f'{parsed.scheme}://{parsed.netloc}'
        vulnerabilities = []
        max_findings = 5

        for path in paths:
            if len(vulnerabilities) >= max_findings:
                break

            test_url = urljoin(base, path)
            try:
                response = self._make_request('GET', test_url)
            except Exception:
                continue

            if not response or response.status_code != 200:
                continue

            # Verify it's not a soft 404
            if len(response.text) < 50:
                continue

            severity, cvss, desc = self._classify_sensitive_path(path, response.text)

            vulnerabilities.append(self._build_vuln(
                name=f'Sensitive Path Exposed: {path}',
                severity=severity,
                category='Security Misconfiguration',
                description=f'{desc}. The path {path} is publicly accessible.',
                impact='Exposed files may reveal credentials, source code, or internal details.',
                remediation='Restrict access to sensitive files. Remove from production. '
                           'Use web server rules to deny access to dot files.',
                cwe='CWE-538',
                cvss=cvss,
                affected_url=test_url,
                evidence=f'HTTP {response.status_code} for {path} ({len(response.text)} bytes)',
            ))

        return vulnerabilities

    def _classify_sensitive_path(self, path: str, body: str) -> tuple:
        """Classify a sensitive path finding."""
        path_lower = path.lower()

        if '.git' in path_lower:
            return 'critical', 9.1, 'Git repository exposed — source code and history accessible'
        elif '.env' in path_lower:
            return 'critical', 9.1, 'Environment file exposed (may contain API keys and passwords)'
        elif any(k in path_lower for k in ('.htpasswd', '/etc/passwd', 'shadow')):
            return 'critical', 9.1, 'Credential/password file exposed'
        elif any(k in path_lower for k in ('phpinfo', 'info.php')):
            return 'medium', 5.3, 'PHP info page exposed (reveals server configuration)'
        elif any(k in path_lower for k in ('admin', 'manager', 'console')):
            return 'medium', 5.3, 'Admin interface publicly accessible'
        elif any(k in path_lower for k in ('swagger', 'openapi', 'graphql', 'actuator')):
            return 'medium', 5.3, 'API documentation/management endpoint exposed'
        elif 'debug' in path_lower:
            return 'high', 7.5, 'Debug interface accessible in production'
        elif any(k in path_lower for k in ('backup', '.bak', '.sql', '.dump')):
            return 'high', 7.5, 'Backup file accessible (may contain sensitive data)'
        elif 'wp-config' in path_lower:
            return 'critical', 9.1, 'WordPress configuration file exposed'
        else:
            return 'medium', 5.3, f'Sensitive file accessible: {path}'

    # ----- Verbose Errors -----
    def _test_verbose_errors(self, url) -> list:
        """Test for verbose error pages that reveal stack traces."""
        vulnerabilities = []

        # Test 1: Trigger 404
        test_url = url.rstrip('/') + '/nonexistent_page_SafeWebAI_test_7291'
        vuln = self._check_error_response(test_url, '404')
        if vuln:
            vulnerabilities.append(vuln)

        # Test 2: Trigger 500 via malformed input
        test_url2 = url.rstrip('/') + "/%27%22%3E%3C"
        vuln = self._check_error_response(test_url2, 'malformed input')
        if vuln and not vulnerabilities:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_error_response(self, test_url: str, trigger: str) -> object:
        """Check an error response for verbose information."""
        try:
            response = self._make_request('GET', test_url)
        except Exception:
            return None

        if not response:
            return None

        error_indicators = [
            ('Traceback (most recent call last)', 'Python stack trace'),
            ('Stack Trace:', 'Stack trace'),
            ('at System.', '.NET stack trace'),
            ('java.lang.', 'Java exception'),
            ('PHP Fatal error', 'PHP fatal error'),
            ('PHP Warning', 'PHP warning'),
            ('SQLSTATE[', 'SQL error message'),
            ('Microsoft OLE DB', 'OLE DB error'),
            ('Django Version:', 'Django debug page'),
            ('DEBUG = True', 'Django debug mode enabled'),
            ("You're seeing this error because", 'Django debug enabled'),
            ('Laravel', 'Laravel debug page'),
            ('Exception in thread', 'Java thread exception'),
            ('at org.apache.', 'Apache stack trace'),
            ('at com.', 'Java stack trace'),
            ('panic:', 'Go panic'),
            ('goroutine', 'Go goroutine dump'),
            ('/usr/local/lib/', 'Server file path exposed'),
            ('C:\\\\', 'Server file path exposed'),
        ]

        for indicator, description in error_indicators:
            if indicator in response.text:
                return self._build_vuln(
                    name='Verbose Error Messages',
                    severity='medium',
                    category='Security Misconfiguration',
                    description=f'The application displays detailed error info ({description}) '
                               f'when triggered by {trigger}.',
                    impact='Debug information reveals technology stack, file paths, and '
                          'potential vulnerabilities to attackers.',
                    remediation='Disable debug mode in production. Configure custom error pages. '
                               'Log errors server-side only.',
                    cwe='CWE-209',
                    cvss=5.3,
                    affected_url=test_url,
                    evidence=f'Trigger: {trigger}\nIndicator: {indicator}',
                )
        return None

    # ----- CSP Analysis -----
    def _analyze_csp(self, page) -> list:
        """Analyze Content-Security-Policy for weaknesses."""
        vulnerabilities = []

        try:
            response = self._make_request('GET', page.url)
        except Exception:
            return vulnerabilities

        if not response:
            return vulnerabilities

        csp = response.headers.get('Content-Security-Policy', '')
        if not csp:
            return vulnerabilities  # Already flagged in _check_security_headers

        issues = []

        # Check for unsafe directives
        if "'unsafe-inline'" in csp:
            issues.append("'unsafe-inline' allows inline scripts, severely weakening CSP")
        if "'unsafe-eval'" in csp:
            issues.append("'unsafe-eval' allows eval(), defeating script injection protection")
        if 'data:' in csp and 'script-src' in csp.split('data:')[0]:
            issues.append("'data:' in script-src allows data: URI script injection")

        # Check for wildcard sources
        directives = csp.split(';')
        for directive in directives:
            d = directive.strip()
            if d and ('* ' in d or d.endswith(' *') or ' *.' in d):
                issues.append(f'Wildcard source in directive: {d.split()[0]}')

        # Check for missing default-src
        if 'default-src' not in csp:
            issues.append('No default-src fallback — unlisted resource types are unrestricted')

        if issues:
            vulnerabilities.append(self._build_vuln(
                name=f'Weak Content Security Policy ({len(issues)} issues)',
                severity='medium',
                category='Security Misconfiguration',
                description='The Content-Security-Policy has weaknesses:\n' +
                           '\n'.join(f'  - {i}' for i in issues),
                impact='A weak CSP provides insufficient protection against XSS and data injection.',
                remediation="Tighten CSP: remove 'unsafe-inline' and 'unsafe-eval', "
                           "use nonces/hashes, avoid wildcards, set default-src 'self'.",
                cwe='CWE-693',
                cvss=4.3,
                affected_url=page.url,
                evidence=f'CSP: {csp[:300]}',
            ))

        return vulnerabilities

    # ----- HSTS -----
    def _check_hsts_config(self, page) -> object:
        """Check HSTS configuration for weaknesses."""
        parsed = urlparse(page.url)
        if parsed.scheme != 'https':
            return None

        try:
            response = self._make_request('GET', page.url)
        except Exception:
            return None

        if not response:
            return None

        hsts = response.headers.get('Strict-Transport-Security', '')
        if not hsts:
            return None  # Already flagged in _check_security_headers

        issues = []

        # Check max-age
        match = re.search(r'max-age=(\d+)', hsts)
        if match:
            max_age = int(match.group(1))
            if max_age < 31536000:  # Less than 1 year
                issues.append(f'max-age={max_age} is less than recommended 31536000 (1 year)')
            if max_age == 0:
                issues.append('max-age=0 effectively disables HSTS')
        else:
            issues.append('No max-age directive found')

        if 'includeSubDomains' not in hsts:
            issues.append('Missing includeSubDomains — subdomains may use insecure HTTP')

        if 'preload' not in hsts:
            issues.append('Missing preload — not eligible for browser HSTS preload list')

        if issues:
            return self._build_vuln(
                name='Weak HSTS Configuration',
                severity='low',
                category='Security Misconfiguration',
                description='HSTS is present but has configuration weaknesses:\n' +
                           '\n'.join(f'  - {i}' for i in issues),
                impact='Incomplete HSTS may leave subdomains or initial connections vulnerable '
                      'to protocol downgrade attacks.',
                remediation='Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                cwe='CWE-319',
                cvss=2.0,
                affected_url=page.url,
                evidence=f'HSTS: {hsts}',
            )

        return None

    # ----- HTML Comments -----
    def _check_html_comments(self, page) -> object:
        """Check HTML comments for sensitive information."""
        body = page.body or ''

        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        sensitive_comments = []

        sensitive_patterns = [
            (r'TODO|FIXME|HACK|BUG|XXX', 'Developer notes'),
            (r'password|passwd|secret|api.?key|token', 'Potential credentials'),
            (r'(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.)', 'Internal IP address'),
            (r'/(?:home|usr|var|etc|opt)/', 'Server file path'),
            (r'[A-Z]:\\\\', 'Server file path (Windows)'),
            (r'(?:jdbc|mysql|postgres|mongodb)://', 'Database connection string'),
            (r'version\s*[:=]\s*\d+\.\d+', 'Version information'),
        ]

        for comment in comments:
            comment_stripped = comment.strip()
            if len(comment_stripped) < 5:
                continue

            for pattern, desc in sensitive_patterns:
                if re.search(pattern, comment_stripped, re.IGNORECASE):
                    sensitive_comments.append((desc, comment_stripped[:100]))
                    break

        if sensitive_comments:
            return self._build_vuln(
                name=f'Sensitive Information in HTML Comments ({len(sensitive_comments)})',
                severity='info',
                category='Security Misconfiguration',
                description='HTML comments contain potentially sensitive information.',
                impact='Developers notes, internal paths, or credentials in HTML comments '
                      'are visible to anyone viewing the page source.',
                remediation='Remove all sensitive information from HTML comments in production. '
                           'Use a build process that strips comments.',
                cwe='CWE-615',
                cvss=0.0,
                affected_url=page.url,
                evidence='\n'.join(f'{desc}: {val}' for desc, val in sensitive_comments[:5]),
            )

        return None
