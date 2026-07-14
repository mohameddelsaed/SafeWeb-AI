"""
ContentDiscoveryTester — Hidden content and sensitive resource discovery.
OWASP A01:2021 — Broken Access Control / A05:2021 — Security Misconfiguration.

Tests for: backup files, config files, admin panels, source code exposure,
debug endpoints, common CMS paths, development artifacts, and database dumps.
Uses smart status-code analysis and content-type validation.
"""
import logging
from urllib.parse import urljoin
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Backup file extensions to test ───────────────────────────────────────────
_BACKUP_EXTENSIONS = [
    '.bak', '.backup', '.old', '.orig', '.save', '.swp', '.swo',
    '.tmp', '.temp', '~', '.copy', '.1', '.2',
    '.dist', '.sample', '.example', '.inc',
]

# ── Source code backup patterns (append to existing filename) ────────────────
_SOURCE_BACKUP_PATTERNS = [
    '{}.bak', '{}.old', '{}.orig', '{}.save', '{}.swp',
    '{}~', '{}.copy', '{}backup', '{}.txt',
]

# ── Admin panel paths ────────────────────────────────────────────────────────
_ADMIN_PATHS = [
    '/admin', '/admin/', '/administrator', '/administrator/',
    '/admin/login', '/admin/dashboard', '/admin/index',
    '/wp-admin/', '/wp-login.php', '/wp-admin/admin-ajax.php',
    '/admin.php', '/login.php', '/adminpanel',
    '/cpanel', '/phpmyadmin/', '/pma/',
    '/adminer.php', '/adminer/',
    '/manager/', '/manage/', '/management/',
    '/dashboard/', '/panel/', '/control/',
    '/webadmin/', '/siteadmin/', '/admin-console/',
    '/system/', '/sys/', '/_admin/',
]

# ── Debug / development endpoints ────────────────────────────────────────────
_DEBUG_PATHS = [
    '/__debug__/', '/debug/', '/debug/default/view',
    '/phpinfo.php', '/info.php', '/phpinfo',
    '/server-info', '/server-status',
    '/elmah.axd', '/trace.axd',
    '/_profiler/', '/_wdt/',  # Symfony profiler
    '/actuator', '/actuator/health', '/actuator/env',  # Spring Boot
    '/actuator/beans', '/actuator/configprops', '/actuator/mappings',
    '/__inspect/', '/_debug_toolbar/',
    '/console/', '/console',  # Rails / Spring console
    '/graphql',  # GraphQL playground
    '/graphiql',
    '/swagger-ui.html', '/swagger-ui/',
    '/api-docs', '/api/docs',
    '/.well-known/openid-configuration',
]

# ── Database dump / export files ─────────────────────────────────────────────
_DB_DUMP_PATHS = [
    '/dump.sql', '/database.sql', '/backup.sql', '/db.sql',
    '/data.sql', '/mysql.sql', '/export.sql',
    '/dump.sql.gz', '/backup.sql.gz', '/database.sql.gz',
    '/db.sqlite', '/db.sqlite3', '/database.db',
    '/data.json', '/export.json', '/export.csv',
    '/dump.tar.gz', '/backup.tar.gz', '/backup.zip',
    '/site.zip', '/www.zip', '/html.zip',
    '/source.zip', '/code.zip', '/app.zip',
]

# ── Sensitive static files ───────────────────────────────────────────────────
_SENSITIVE_FILES = [
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/security.txt', '/.well-known/security.txt',
    '/humans.txt', '/readme.html', '/readme.txt', '/README.md',
    '/CHANGELOG.md', '/CHANGELOG.txt', '/changelog.txt',
    '/license.txt', '/LICENSE',
    '/package.json', '/package-lock.json', '/yarn.lock',
    '/composer.json', '/composer.lock',
    '/Gemfile', '/Gemfile.lock',
    '/requirements.txt', '/Pipfile', '/Pipfile.lock',
    '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
    '/.dockerenv',
    '/Makefile', '/Gruntfile.js', '/gulpfile.js',
    '/webpack.config.js', '/vite.config.js', '/tsconfig.json',
    '/.babelrc', '/.eslintrc', '/.prettierrc',
    '/Procfile', '/Vagrantfile', '/Jenkinsfile',
    '/.travis.yml', '/.github/workflows',
]

# Content types that indicate sensitive data exposure
_SENSITIVE_CONTENT_TYPES = {
    'application/json', 'application/xml', 'text/xml',
    'application/sql', 'application/x-sql',
    'application/zip', 'application/gzip',
    'application/x-sqlite3',
    'application/octet-stream',
}


class ContentDiscoveryTester(BaseTester):
    """Discover hidden content, backup files, admin panels, and debug endpoints."""

    TESTER_NAME = 'Content Discovery'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        base_url = self._get_base_url(page.url)

        # Backup file detection
        vulns = self._check_backup_files(page, base_url)
        vulnerabilities.extend(vulns)

        # Admin panel discovery
        if depth in ('medium', 'deep'):
            vulns = self._check_admin_panels(base_url)
            vulnerabilities.extend(vulns)

        # Debug / development endpoints
        vulns = self._check_debug_endpoints(base_url, depth)
        vulnerabilities.extend(vulns)

        # Database dump / export files (medium/deep)
        if depth in ('medium', 'deep'):
            vulns = self._check_database_dumps(base_url)
            vulnerabilities.extend(vulns)

        # Sensitive static files
        vulns = self._check_sensitive_files(base_url, depth)
        vulnerabilities.extend(vulns)

        # Source code backup detection (deep)
        if depth == 'deep':
            vulns = self._check_source_backups(page, base_url)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _get_base_url(self, url):
        """Extract base URL (scheme + host) from a full URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return f'{parsed.scheme}://{parsed.netloc}'

    def _probe_path(self, base_url, path, timeout=8):
        """Probe a path and return (response, full_url) if it exists."""
        full_url = urljoin(base_url, path)
        response = self._make_request('GET', full_url, timeout=timeout)
        return response, full_url

    def _is_real_page(self, response):
        """Check if response is a real page (not a custom 404 or redirect)."""
        if not response:
            return False
        if response.status_code not in (200, 301, 302, 403):
            return False
        # Avoid false positives from custom 404 pages
        body = (response.text or '').lower()
        false_positive_indicators = [
            'page not found', '404 not found', 'not found',
            'does not exist', 'no such page', 'error 404',
        ]
        if response.status_code == 200:
            for indicator in false_positive_indicators:
                if indicator in body and len(body) < 5000:
                    return False
        return True

    def _check_backup_files(self, page, base_url):
        """Check for backup copies of the current page and common files."""
        vulnerabilities = []

        # Test backup extensions on the current page path
        from urllib.parse import urlparse
        parsed = urlparse(page.url)
        page_path = parsed.path

        if page_path and page_path != '/':
            for ext in _BACKUP_EXTENSIONS[:8]:
                backup_path = page_path + ext
                response, full_url = self._probe_path(base_url, backup_path)
                if self._is_real_page(response) and response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    # Backup files should return source code, not rendered HTML
                    if 'text/html' not in content_type or self._looks_like_source(response.text):
                        vulnerabilities.append(self._build_vuln(
                            name=f'Backup File Exposed: {backup_path}',
                            severity='high',
                            category='Content Discovery',
                            description=f'A backup copy of "{page_path}" was found at '
                                       f'"{backup_path}". Backup files often contain '
                                       f'source code, configuration, and credentials.',
                            impact='Source code exposure reveals application logic, database '
                                  'credentials, API keys, and internal architecture.',
                            remediation='Remove all backup files from the web root. '
                                       'Configure the web server to block backup file extensions. '
                                       'Use .htaccess or nginx rules to deny access to .bak, .old, etc.',
                            cwe='CWE-530',
                            cvss=7.5,
                            affected_url=full_url,
                            evidence=f'Backup file accessible: {backup_path}\n'
                                    f'Content-Type: {content_type}\n'
                                    f'Size: {len(response.text)} bytes',
                        ))
                        break  # One backup finding per page

        return vulnerabilities

    def _check_admin_panels(self, base_url):
        """Discover accessible admin panel paths."""
        vulnerabilities = []
        found_admin = False

        for path in _ADMIN_PATHS:
            response, full_url = self._probe_path(base_url, path)
            if not self._is_real_page(response):
                continue

            if response.status_code == 200:
                # Accessible admin panel
                body = (response.text or '').lower()
                is_login = any(kw in body for kw in ['login', 'password', 'sign in', 'username', 'authenticate'])
                severity = 'medium' if is_login else 'high'
                desc_extra = ' A login form was detected.' if is_login else ' No authentication required!'

                vulnerabilities.append(self._build_vuln(
                    name=f'Admin Panel Discovered: {path}',
                    severity=severity,
                    category='Content Discovery',
                    description=f'An administrative interface was found at "{path}".{desc_extra}',
                    impact='Admin panels enable full application control. If accessible without '
                          'authentication or with weak credentials, complete compromise is possible.',
                    remediation='Restrict admin panel access to specific IP ranges. '
                               'Use strong authentication (MFA). Move admin panels to '
                               'non-standard paths. Implement rate limiting on login.',
                    cwe='CWE-200',
                    cvss=6.5 if is_login else 8.0,
                    affected_url=full_url,
                    evidence=f'Admin path: {path}\nStatus: {response.status_code}\n'
                            f'Has login form: {is_login}',
                ))
                found_admin = True

            elif response.status_code == 403:
                # Exists but forbidden — information disclosure
                vulnerabilities.append(self._build_vuln(
                    name=f'Admin Panel Exists (Forbidden): {path}',
                    severity='info',
                    category='Content Discovery',
                    description=f'Admin panel at "{path}" returned 403 Forbidden, confirming '
                               f'its existence. Access control is in place but the path is known.',
                    impact='Confirming admin panel existence helps attackers focus brute-force '
                          'and bypass attempts.',
                    remediation='Return 404 instead of 403 for admin paths to avoid confirmation. '
                               'Use non-standard admin panel URLs.',
                    cwe='CWE-200',
                    cvss=2.0,
                    affected_url=full_url,
                    evidence=f'Admin path: {path}\nStatus: 403 Forbidden',
                ))

            if found_admin:
                break  # One accessible admin panel is enough

        return vulnerabilities

    def _check_debug_endpoints(self, base_url, depth):
        """Discover exposed debug and development endpoints."""
        vulnerabilities = []
        paths = _DEBUG_PATHS[:10] if depth == 'shallow' else _DEBUG_PATHS

        for path in paths:
            response, full_url = self._probe_path(base_url, path)
            if not self._is_real_page(response):
                continue

            if response.status_code == 200:
                severity = 'critical' if any(kw in path for kw in
                    ['phpinfo', 'actuator/env', 'actuator/configprops', 'elmah', 'trace']
                ) else 'high'

                vulnerabilities.append(self._build_vuln(
                    name=f'Debug Endpoint Exposed: {path}',
                    severity=severity,
                    category='Content Discovery',
                    description=f'A debug/development endpoint was found at "{path}". '
                               f'Debug endpoints expose internal application state, '
                               f'environment variables, and system configuration.',
                    impact='Debug endpoints may reveal: database credentials, API keys, '
                          'internal IP addresses, framework versions, OS details, '
                          'and complete application configuration.',
                    remediation='Disable all debug endpoints in production. '
                               'Set DEBUG=False (Django), SPRING_PROFILES_ACTIVE=prod (Spring). '
                               'Remove phpinfo files. Block debug paths at the web server level.',
                    cwe='CWE-215',
                    cvss=9.0 if severity == 'critical' else 7.5,
                    affected_url=full_url,
                    evidence=f'Debug endpoint: {path}\nStatus: {response.status_code}\n'
                            f'Size: {len(response.text or "")} bytes',
                ))

                if len(vulnerabilities) >= 3:
                    break  # Limit findings for debug endpoints

        return vulnerabilities

    def _check_database_dumps(self, base_url):
        """Check for exposed database dump and export files."""
        vulnerabilities = []

        for path in _DB_DUMP_PATHS:
            response, full_url = self._probe_path(base_url, path, timeout=5)
            if not response:
                continue

            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                content_length = int(response.headers.get('Content-Length', 0) or len(response.text or ''))

                # Must have substantial content
                if content_length < 100:
                    continue

                # Check content type or content for SQL/data indicators
                is_sql = any(kw in (response.text or '').lower()[:1000]
                            for kw in ['create table', 'insert into', 'drop table',
                                      'mysqldump', '-- dump'])
                is_binary = any(ct in content_type for ct in
                               ['zip', 'gzip', 'sqlite', 'octet-stream'])

                if is_sql or is_binary or path.endswith(('.sql', '.sqlite', '.db')):
                    vulnerabilities.append(self._build_vuln(
                        name=f'Database Dump Exposed: {path}',
                        severity='critical',
                        category='Content Discovery',
                        description=f'A database dump/export file was found at "{path}". '
                                   f'This file likely contains the entire database contents.',
                        impact='Complete database exposure including user credentials, '
                              'personal data, business records, and application secrets.',
                        remediation='Remove all database dumps from the web root immediately. '
                                   'Store backups in secure, non-web-accessible locations. '
                                   'Use signed URLs for authorized backup downloads.',
                        cwe='CWE-530',
                        cvss=9.8,
                        affected_url=full_url,
                        evidence=f'Database file: {path}\n'
                                f'Content-Type: {content_type}\n'
                                f'Size: {content_length} bytes',
                    ))
                    break  # One DB dump finding is critical enough

        return vulnerabilities

    def _check_sensitive_files(self, base_url, depth):
        """Check for exposed sensitive static files."""
        vulnerabilities = []
        files = _SENSITIVE_FILES[:15] if depth == 'shallow' else _SENSITIVE_FILES

        high_risk = {'/package.json', '/composer.json', '/requirements.txt',
                     '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
                     '/.dockerenv', '/Jenkinsfile', '/webpack.config.js'}

        for path in files:
            response, full_url = self._probe_path(base_url, path, timeout=5)
            if not response or response.status_code != 200:
                continue

            content = response.text or ''
            if len(content) < 10:
                continue

            severity = 'medium' if path in high_risk else 'low'

            vulnerabilities.append(self._build_vuln(
                name=f'Sensitive File Exposed: {path}',
                severity=severity,
                category='Content Discovery',
                description=f'The file "{path}" is publicly accessible. It may reveal '
                           f'dependencies, infrastructure details, or internal configuration.',
                impact='Exposed config/dependency files reveal technology stack, versions, '
                      'internal paths, and may contain secrets.',
                remediation=f'Block access to "{path}" in web server configuration. '
                           'Move sensitive files outside the web root.',
                cwe='CWE-538',
                cvss=5.3 if severity == 'medium' else 3.1,
                affected_url=full_url,
                evidence=f'File: {path}\nSize: {len(content)} bytes\n'
                        f'Preview: {content[:200]}',
            ))

            if len(vulnerabilities) >= 5:
                break

        return vulnerabilities

    def _check_source_backups(self, page, base_url):
        """Deep scan: check for common source code backup file patterns."""
        vulnerabilities = []
        # Try common whole-site backup names
        site_backups = ['/backup.zip', '/site.zip', '/www.zip', '/html.zip',
                       '/source.tar.gz', '/backup.tar.gz', '/web.zip']

        for path in site_backups:
            response, full_url = self._probe_path(base_url, path, timeout=5)
            if response and response.status_code == 200:
                content_length = int(response.headers.get('Content-Length', 0) or 0)
                content_type = response.headers.get('Content-Type', '').lower()
                if content_length > 1000 and ('zip' in content_type or 'gzip' in content_type
                                              or 'octet' in content_type):
                    vulnerabilities.append(self._build_vuln(
                        name=f'Source Code Archive Exposed: {path}',
                        severity='critical',
                        category='Content Discovery',
                        description=f'A source code archive was found at "{path}" '
                                   f'({content_length} bytes). This may contain the '
                                   f'entire application source code.',
                        impact='Full source code exposure reveals all application logic, '
                              'hardcoded credentials, API keys, database schemas, '
                              'and internal architecture.',
                        remediation='Remove all archive files from the web root immediately. '
                                   'Audit the archive contents for secret exposure.',
                        cwe='CWE-530',
                        cvss=9.8,
                        affected_url=full_url,
                        evidence=f'Archive: {path}\n'
                                f'Content-Type: {content_type}\n'
                                f'Size: {content_length} bytes',
                    ))
                    break

        return vulnerabilities

    def _looks_like_source(self, text):
        """Check if text content looks like source code rather than rendered HTML."""
        if not text:
            return False
        indicators = ['<?php', '<?=', 'import ', 'from ', 'require(', 'module.exports',
                      'def ', 'class ', 'function ', 'private ', 'public ',
                      'DB_PASSWORD', 'SECRET_KEY', 'API_KEY', 'DATABASE_URL']
        return any(ind in text[:2000] for ind in indicators)
