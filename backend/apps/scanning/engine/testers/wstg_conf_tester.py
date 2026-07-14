"""
WSTGConfTester — OWASP WSTG-CONF gap coverage.
Maps to: WSTG-CONF-04 (Backup/Unreferenced Files), WSTG-CONF-05 (HTTP Method Testing),
         WSTG-CONF-07 (HTTP Strict Transport), WSTG-CONF-08 (RIA Cross-Domain Policy),
         WSTG-CONF-10 (Admin Interfaces), WSTG-CONF-11 (HTTP Methods on Web Apps).

Fills configuration testing gaps identified in Phase 46.
"""
import re
import logging
from urllib.parse import urlparse

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Backup/unreferenced file patterns (WSTG-CONF-04)
BACKUP_EXTENSIONS = [
    '.bak', '.backup', '.old', '.orig', '.copy', '.tmp',
    '.swp', '.swo', '.inc', '.cfg', '.config', '.conf',
    '.ini', '.log', '.sql', '.json~', '.xml~',
]

# Dangerous HTTP methods to test (WSTG-CONF-05)
DANGEROUS_METHODS = ['TRACE', 'TRACK', 'DELETE', 'PUT', 'PATCH', 'CONNECT', 'OPTIONS']

# RIA cross-domain file paths (WSTG-CONF-08)
CROSS_DOMAIN_PATHS = [
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',
    '/crossorigin.xml',
]

# Admin interface paths (WSTG-CONF-10)
ADMIN_PATHS = [
    '/admin', '/admin/', '/administrator', '/admin/login',
    '/wp-admin', '/phpmyadmin', '/pma', '/cpanel',
    '/manage', '/management', '/console', '/control',
    '/backend', '/dashboard', '/panel',
]


class WSTGConfTester(BaseTester):
    """WSTG-CONF: Configuration and Deployment Management Testing."""

    TESTER_NAME = 'WSTG-CONF'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        base = self._base_url(page.url)

        # WSTG-CONF-04: Backup/unreferenced files
        if depth in ('medium', 'deep'):
            vulns = self._test_backup_files(page.url)
            vulnerabilities.extend(vulns)

        # WSTG-CONF-05: HTTP method testing
        vuln = self._test_http_methods(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-CONF-08: RIA cross-domain policy
        vulns = self._test_ria_cross_domain(base)
        vulnerabilities.extend(vulns)

        # WSTG-CONF-10: Admin interfaces
        if depth == 'deep':
            vulns = self._test_admin_interfaces(base)
            vulnerabilities.extend(vulns)

        # WSTG-CONF-11: File extension handling
        if depth in ('medium', 'deep'):
            vuln = self._test_file_extension_handling(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    # ── WSTG-CONF-04: Backup/Unreferenced Files ───────────────────────────────

    def _test_backup_files(self, url: str) -> list:
        """Check for backup/config files alongside the current URL."""
        found = []
        parsed = urlparse(url)
        path = parsed.path

        # Build candidate backup paths for the current page's path
        base_path = path.rstrip('/')
        if not base_path:
            base_path = '/index'

        test_paths = []
        for ext in BACKUP_EXTENSIONS:
            test_paths.append(base_path + ext)
        # Also try with original extension replaced
        if '.' in base_path.split('/')[-1]:
            stem = base_path.rsplit('.', 1)[0]
            for ext in BACKUP_EXTENSIONS:
                test_paths.append(stem + ext)

        base_url = f'{parsed.scheme}://{parsed.netloc}'
        for test_path in test_paths[:12]:  # cap at 12
            test_url = base_url + test_path
            resp = self._make_request('GET', test_url)
            if not resp or resp.status_code not in (200,):
                continue

            found.append(self._build_vuln(
                name=f'Backup/Temporary File Accessible: {test_path}',
                severity='high',
                category='WSTG-CONF-04: Backup and Unreferenced Files',
                description=f'A backup or temporary copy of the file is accessible at {test_path}. '
                            f'These files often contain unobfuscated source code, credentials, '
                            f'or configuration details.',
                impact='Attackers can read application source code, discover credentials, '
                       'understand database structure, and plan targeted attacks.',
                remediation='Remove all backup, swap, and temporary files from the web root. '
                            'Configure the web server to deny access to common backup extensions.',
                cwe='CWE-530',
                cvss=7.5,
                affected_url=test_url,
                evidence=f'HTTP 200 returned for {test_path}. '
                         f'Response length: {len(resp.content)} bytes.',
            ))
        return found

    # ── WSTG-CONF-05: HTTP Method Testing ─────────────────────────────────────

    def _test_http_methods(self, url: str):
        """Detect dangerous enabled HTTP methods."""
        enabled = []

        # First try an OPTIONS request to enumerate
        resp = self._make_request('OPTIONS', url)
        if resp:
            allow = resp.headers.get('Allow', '') + resp.headers.get('Public', '')
            for method in DANGEROUS_METHODS:
                if method in allow:
                    enabled.append(method)

            # TRACE specifically: send a TRACE request and check body
            if not enabled or 'TRACE' in allow:
                trace_resp = self._make_request('TRACE', url)
                if trace_resp and 'TRACE' in (trace_resp.text or '').upper()[:200]:
                    if 'TRACE' not in enabled:
                        enabled.append('TRACE')

        if not enabled:
            return None

        dangerous_present = [m for m in enabled if m in ('TRACE', 'TRACK', 'DELETE', 'PUT')]
        if not dangerous_present:
            return None

        return self._build_vuln(
            name=f'Dangerous HTTP Methods Enabled: {", ".join(dangerous_present)}',
            severity='medium',
            category='WSTG-CONF-05: HTTP Method Testing',
            description=f'The web server allows the following dangerous HTTP methods: '
                        f'{", ".join(dangerous_present)}. TRACE enables Cross-Site Tracing (XST) '
                        f'attacks; DELETE/PUT can allow unauthorized content modification.',
            impact='TRACE can be used to steal cookies via XST. '
                   'PUT/DELETE allow unauthorized file creation or deletion.',
            remediation='Disable unused HTTP methods in web server configuration. '
                        'For Apache: `LimitExcept GET POST OPTIONS`. '
                        'For Nginx: `if ($request_method !~ ^(GET|POST|HEAD)$)`. '
                        'Disable TRACE entirely.',
            cwe='CWE-650',
            cvss=5.3,
            affected_url=url,
            evidence=f'OPTIONS Allow header contains: {allow.strip()[:300]}',
        )

    # ── WSTG-CONF-08: RIA Cross-Domain Policy ────────────────────────────────

    def _test_ria_cross_domain(self, base: str) -> list:
        """Check for permissive RIA cross-domain policy files."""
        found = []
        for path in CROSS_DOMAIN_PATHS:
            url = base + path
            resp = self._make_request('GET', url)
            if not resp or resp.status_code != 200:
                continue

            body = resp.text or ''
            # Check for wildcard allow-access-from in crossdomain.xml
            if re.search(r'allow-access-from\s+domain=["\*]', body, re.IGNORECASE):
                found.append(self._build_vuln(
                    name=f'Permissive RIA Cross-Domain Policy in {path}',
                    severity='high',
                    category='WSTG-CONF-08: RIA Cross-Domain Policy',
                    description=f'The cross-domain policy file {path} allows access from all '
                                f'domains (wildcard *). This enables any Flash/Silverlight application '
                                f'to make cross-origin requests to this server.',
                    impact='Cross-site request forgery from any origin is possible. '
                           'Attackers can steal cookies, credentials, or sensitive data.',
                    remediation='Restrict allow-access-from to specific trusted domains. '
                                'Remove or restrict crossdomain.xml if Flash/Silverlight is not used.',
                    cwe='CWE-942',
                    cvss=7.4,
                    affected_url=url,
                    evidence=body[:500],
                ))
            elif 'allow-access-from' in body.lower():
                found.append(self._build_vuln(
                    name=f'RIA Cross-Domain Policy File Present: {path}',
                    severity='low',
                    category='WSTG-CONF-08: RIA Cross-Domain Policy',
                    description=f'A cross-domain policy file was found at {path}. '
                                f'Review whether the allowed origins are appropriate.',
                    impact='Overly permissive configurations allow cross-origin data access.',
                    remediation='Review and restrict cross-domain policy to required domains only.',
                    cwe='CWE-942',
                    cvss=3.1,
                    affected_url=url,
                    evidence=body[:300],
                ))
        return found

    # ── WSTG-CONF-10: Admin Interfaces ────────────────────────────────────────

    def _test_admin_interfaces(self, base: str) -> list:
        """Discover exposed administrative interfaces."""
        found = []
        for path in ADMIN_PATHS:
            url = base + path
            resp = self._make_request('GET', url)
            if not resp:
                continue

            # Positive indicators: 200, 401, 403 with admin-like content
            if resp.status_code == 200:
                body = (resp.text or '').lower()
                if any(k in body for k in ('login', 'admin', 'password', 'sign in', 'dashboard')):
                    found.append(self._build_vuln(
                        name=f'Administrative Interface Exposed: {path}',
                        severity='high',
                        category='WSTG-CONF-10: Application Infrastructure Admin Interfaces',
                        description=f'An administrative interface is accessible at {path}. '
                                    f'Admin panels should not be publicly reachable.',
                        impact='Brute-force or credential stuffing attacks can be launched '
                               'directly against the admin interface.',
                        remediation='Restrict admin interface access by IP allowlist, VPN, '
                                    'or move it to a non-standard path not guessable from common wordlists.',
                        cwe='CWE-284',
                        cvss=7.2,
                        affected_url=url,
                        evidence=f'HTTP 200, admin login form detected at {path}.',
                    ))
                    break  # Report first found

        return found

    # ── WSTG-CONF-11: File Extension Handling ─────────────────────────────────

    def _test_file_extension_handling(self, url: str):
        """
        Test if double extensions bypass file type restrictions.
        E.g., script.php.txt executed as PHP.
        """
        parsed = urlparse(url)
        # Only relevant if the URL doesn't already have an extension
        path = parsed.path
        if '.' in path.split('/')[-1]:
            return None  # skip if already has extension

        # Append a test double-extension path
        test_url = url.rstrip('/') + '/test.php.txt'
        resp = self._make_request('GET', test_url)
        if not resp:
            return None

        if resp.status_code == 200:
            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' in content_type or 'application/x-php' in content_type:
                return self._build_vuln(
                    name='Potential Double-Extension File Handling Issue',
                    severity='medium',
                    category='WSTG-CONF-11: File Extension Handling',
                    description='The server returned HTTP 200 for a double-extension filename '
                                '(.php.txt), which may indicate that the web server could execute '
                                'scripts with secondary extensions in certain configurations.',
                    impact='Attackers may be able to upload scripts with double extensions '
                           'to bypass file upload restrictions and achieve code execution.',
                    remediation='Configure web server to handle file types strictly. '
                                'For Apache, disable AddHandler/AddType for dangerous extensions '
                                'unless the exact full extension matches.',
                    cwe='CWE-434',
                    cvss=5.0,
                    affected_url=test_url,
                    evidence=f'HTTP 200 for .php.txt, Content-Type: {content_type}',
                )
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _base_url(self, url: str) -> str:
        p = urlparse(url)
        return f'{p.scheme}://{p.netloc}'
