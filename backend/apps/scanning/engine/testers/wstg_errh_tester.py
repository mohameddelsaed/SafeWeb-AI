"""
WSTGErrorHandlingTester — OWASP WSTG-ERRH coverage.
Maps to: WSTG-ERRH-01 (Improper Error Handling), WSTG-ERRH-02 (Stack Traces).

Fills error handling testing gaps identified in Phase 46.
Note: Basic verbose error testing exists in LoggingTester; this tester
provides deeper, more targeted WSTG-ERRH coverage.
"""
import re
import logging

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Trigger paths and payloads to provoke server errors
ERROR_TRIGGERS = [
    ('GET', '{url}/%00'),                   # Null byte
    ('GET', '{url}/../../../../etc/passwd'),  # Path traversal
    ('GET', '{url}/<script>'),               # XSS attempt
    ('GET', '{url}?id=1\''),                 # SQL quote
    ('GET', '{url}?__debug=1'),              # Debug endpoint
    ('GET', '{url}?format=xml'),             # Format change
    ('GET', '{url}/undefined'),              # Non-existent path
    ('POST', '{url}'),                       # Empty POST body
]

# Stack trace / internal error patterns across frameworks
STACK_TRACE_PATTERNS = [
    # Python
    r'Traceback \(most recent call last\)',
    r'File "[^"]+\.py", line \d+',
    r'django\.core\.exceptions',
    r'flask\.exceptions',
    # Java
    r'at [a-zA-Z0-9_$.]+\([^)]+\.java:\d+\)',
    r'java\.lang\.\w+Exception',
    r'java\.sql\.\w+Exception',
    r'org\.springframework',
    r'Caused by:',
    # PHP
    r'PHP Fatal error:',
    r'PHP Warning:',
    r'Call to undefined function',
    r'on line \d+',
    # .NET
    r'System\.\w+\.\w+Exception',
    r'at System\.',
    r'Microsoft\.AspNet',
    # Ruby
    r'ActionController::',
    r'NoMethodError',
    # Node.js
    r'at Object\.<anonymous>',
    r'at Module\._compile',
    # Database errors
    r'ORA-\d{5}:',
    r'SQLSTATE\[',
    r'Microsoft OLE DB Provider',
    r'mysql_fetch_array',
    r'You have an error in your SQL syntax',
    r'pg_query\(\)',
    r'SQLITE_ERROR',
]

# Debug mode indicators
DEBUG_INDICATORS = [
    'DEBUG = True',
    'debug mode is on',
    'development server',
    'werkzeug debugger',
    'interactive debugger',
    'padrino debugger',
    'django debug toolbar',
    '__debug__',
    'RAILS_ENV.*development',
    'NODE_ENV.*development',
]

# Path disclosure patterns
PATH_DISCLOSURE_PATTERNS = [
    r'[Cc]:\\[Uu]sers\\[^<\s]+',      # Windows paths
    r'/home/[^/\s<]+/',                  # Linux home dirs
    r'/var/www/[^<\s]+',                 # Web roots
    r'/opt/[^<\s]+\.py',                 # App file paths
    r'/srv/[^<\s]+',
    r'[A-Za-z]:\\inetpub\\',             # IIS path
]


class WSTGErrorHandlingTester(BaseTester):
    """WSTG-ERRH: Error Handling — verbose errors, stack traces, debug mode, path disclosure."""

    TESTER_NAME = 'WSTG-ERRH'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # WSTG-ERRH-01/02: Verbose errors and stack traces
        vuln = self._test_verbose_errors(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Debug mode detection
        vuln = self._test_debug_mode(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Path disclosure in existing page content
        vuln = self._test_path_disclosure_in_page(page)
        if vuln:
            vulnerabilities.append(vuln)

        # Deep: test more error triggers
        if depth == 'deep':
            vuln = self._test_database_errors(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    # ── WSTG-ERRH-01/02: Verbose Errors & Stack Traces ────────────────────────

    def _test_verbose_errors(self, url: str):
        """Probe the application with malformed inputs and inspect error responses."""
        for method, url_template in ERROR_TRIGGERS[:6]:
            test_url = url_template.format(url=url.rstrip('/'))
            data = None
            if method == 'POST':
                data = {}

            resp = self._make_request(method, test_url, data=data)
            if not resp:
                continue

            body = resp.text or ''

            for pattern in STACK_TRACE_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    return self._build_vuln(
                        name='Stack Trace / Internal Details Exposed in Error Response',
                        severity='medium',
                        category='WSTG-ERRH-02: Testing for Stack Traces',
                        description='The application returns a stack trace or internal error '
                                    'details when handling malformed input. This reveals framework, '
                                    'language, file paths, and code structure to attackers.',
                        impact='Detailed error messages accelerate attacker reconnaissance: '
                               'framework versions, internal file paths, database queries, and '
                               'source code context are all revealed.',
                        remediation='Configure production error handling to return generic error pages. '
                                    'Disable DEBUG mode in all production environments. '
                                    'Log detailed errors server-side and return a generic message to clients.',
                        cwe='CWE-209',
                        cvss=5.3,
                        affected_url=test_url,
                        evidence=f'Stack trace pattern matched: {pattern}',
                    )
        return None

    # ── Debug Mode Detection ──────────────────────────────────────────────────

    def _test_debug_mode(self, url: str):
        """Check for debug-mode indicators: interactive debugger, debug toolbars, etc."""
        # Check common debug paths
        debug_paths = [
            '/__debug__/', '/debug', '/debug/', '?debug=1',
            '?__debug__=1', '/console', '/_profiler/', '/phpinfo.php',
        ]
        base = url.rstrip('/')
        for path in debug_paths:
            test_url = base + path if not path.startswith('?') else base + path
            resp = self._make_request('GET', test_url)
            if not resp or resp.status_code not in (200,):
                continue

            body = (resp.text or '').lower()
            for indicator in DEBUG_INDICATORS:
                if indicator.lower() in body:
                    return self._build_vuln(
                        name='Debug Mode or Development Interface Enabled in Production',
                        severity='critical',
                        category='WSTG-ERRH-01: Testing for Improper Error Handling',
                        description=f'A debug mode or interactive debugger interface is accessible '
                                    f'at {test_url}. Debug interfaces expose internal state, allow '
                                    f'arbitrary code execution, and reveal sensitive configuration.',
                        impact='Full application compromise: attackers can execute arbitrary Python/'
                               'Ruby/Node code, read environment variables, and access credentials.',
                        remediation='Disable DEBUG mode before deploying to production. '
                                    'Remove/restrict debug endpoints. Use FLASK_ENV=production, '
                                    'DJANGO_DEBUG=False, NODE_ENV=production.',
                        cwe='CWE-94',
                        cvss=10.0,
                        affected_url=test_url,
                        evidence=f'Debug indicator found: {indicator}',
                    )
        return None

    # ── Path Disclosure ───────────────────────────────────────────────────────

    def _test_path_disclosure_in_page(self, page):
        """Detect server file system paths exposed in page body."""
        body = getattr(page, 'body', '') or ''
        for pattern in PATH_DISCLOSURE_PATTERNS:
            match = re.search(pattern, body)
            if match:
                return self._build_vuln(
                    name='Server File System Path Disclosed in Page Content',
                    severity='low',
                    category='WSTG-ERRH-01: Testing for Improper Error Handling',
                    description='The page response contains what appears to be a server-side '
                                f'file system path: "{match.group(0)}". Exposing internal paths '
                                f'aids attacker reconnaissance.',
                    impact='Reveals server directory structure, technology stack, '
                           'and potential targets for path traversal attacks.',
                    remediation='Ensure error messages, comments, and page content do not expose '
                                'server file system paths. Implement custom error pages.',
                    cwe='CWE-200',
                    cvss=3.1,
                    affected_url=page.url,
                    evidence=f'Path disclosed: {match.group(0)[:200]}',
                )
        return None

    # ── Database Error Detection ──────────────────────────────────────────────

    def _test_database_errors(self, url: str):
        """Trigger database errors and check if they leak query structure."""
        db_triggers = [
            url + "?id=1'--",
            url + "?id=1 AND 1=CONVERT(int,CHAR(0x41))",
            url + "?id=1/**/UNION/**/SELECT/**/NULL--",
        ]
        db_error_patterns = [
            r'You have an error in your SQL syntax',
            r'SQLSTATE\[',
            r'ORA-\d{5}',
            r'Microsoft OLE DB Provider for ODBC Drivers',
            r'pg_query\(\): Query failed',
            r'sqlite3\.OperationalError',
            r"near \"[^\"]+\": syntax error",
        ]
        for test_url in db_triggers:
            resp = self._make_request('GET', test_url)
            if not resp:
                continue
            body = resp.text or ''
            for pattern in db_error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return self._build_vuln(
                        name='Database Error Message Disclosed in HTTP Response',
                        severity='high',
                        category='WSTG-ERRH-01: Testing for Improper Error Handling',
                        description='A database error message was returned in the HTTP response. '
                                    'This exposes the DBMS type, query structure, and may indicate '
                                    'SQL injection vulnerability.',
                        impact='Accelerates SQL injection exploitation by revealing query structure '
                               'and DBMS type. May directly indicate an injectable parameter.',
                        remediation='Implement generic error handling for database errors. '
                                    'Do not expose SQLSTATE, ORA-, or MySQL error messages to clients. '
                                    'Use parameterized queries to prevent the injection.',
                        cwe='CWE-209',
                        cvss=7.5,
                        affected_url=test_url,
                        evidence=f'DB error match: {pattern}',
                    )
        return None
