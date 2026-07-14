"""
WSTGInfoTester — OWASP WSTG-INFO gap coverage.
Maps to: WSTG-INFO-01 (Search Engine Discovery), WSTG-INFO-02 (Web Server Fingerprint),
         WSTG-INFO-03 (Metafiles), WSTG-INFO-05 (Content Enumeration / Entrypoints).

Fills coverage gaps identified in Phase 46.
"""
import re
import logging
from urllib.parse import urlparse

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Sensitive metafiles to probe
WSTG_META_PATHS = [
    '/robots.txt',
    '/sitemap.xml',
    '/sitemap_index.xml',
    '/.well-known/security.txt',
    '/.well-known/openid-configuration',
    '/.htaccess',
    '/.htpasswd',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',
    '/humans.txt',
]

# Patterns in robots.txt that indicate hidden paths
DISALLOW_PATTERN = re.compile(r'^Disallow:\s*(.+)$', re.MULTILINE | re.IGNORECASE)

# Server / tech header names
FINGERPRINT_HEADERS = [
    'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
    'X-Generator', 'X-Application-Context', 'X-Runtime', 'X-Version',
    'Via', 'X-Forwarded-Server',
]


class WSTGInfoTester(BaseTester):
    """WSTG-INFO: Information Gathering — search-engine discovery, entrypoints, metafiles."""

    TESTER_NAME = 'WSTG-INFO'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        base = self._base_url(page.url)

        # WSTG-INFO-03: Enumerate web server metafiles
        vulns = self._test_metafiles(base)
        vulnerabilities.extend(vulns)

        # WSTG-INFO-02: Web server fingerprinting via headers
        vuln = self._test_server_fingerprint(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-INFO-05: Map application entry points from page source
        if depth in ('medium', 'deep'):
            vulns = self._test_entrypoints(page)
            vulnerabilities.extend(vulns)

        # WSTG-INFO-01: Search engine discovery — check for overly permissive robots.txt
        if depth in ('medium', 'deep'):
            vuln = self._test_robots_disclosure(base)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    # ── WSTG-INFO-03 ──────────────────────────────────────────────────────────

    def _test_metafiles(self, base: str) -> list:
        """Probe sensitive metafiles and report accessible ones."""
        found = []
        for path in WSTG_META_PATHS:
            url = base + path
            resp = self._make_request('GET', url)
            if not resp or resp.status_code not in (200, 301, 302):
                continue
            if resp.status_code in (301, 302):
                loc = resp.headers.get('Location', '')
                if not self._is_same_origin(base, loc):
                    continue

            # .htpasswd / .htaccess — direct access is a critical risk
            if path in ('/.htaccess', '/.htpasswd'):
                found.append(self._build_vuln(
                    name=f'Sensitive File Accessible: {path}',
                    severity='high',
                    category='WSTG-INFO-03: Metafiles',
                    description=f'The file {path} is directly accessible. This file may '
                                f'contain authentication credentials or server configuration.',
                    impact='Attackers can retrieve server configurations, credential hashes, '
                           'or directory rewrite rules.',
                    remediation=f'Deny public access to {path} via web server configuration. '
                                f'Move sensitive config files outside the web root.',
                    cwe='CWE-548',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'HTTP {resp.status_code} returned for {path}',
                ))
                continue

            # robots.txt / sitemap.xml — low severity but notable
            if path in ('/robots.txt', '/sitemap.xml', '/sitemap_index.xml'):
                continue  # handled in _test_robots_disclosure

            # .well-known/openid-configuration — informational
            if 'openid-configuration' in path:
                found.append(self._build_vuln(
                    name='OpenID Connect Configuration Exposed',
                    severity='info',
                    category='WSTG-INFO-03: Metafiles',
                    description='The OpenID Connect discovery configuration is publicly accessible '
                                'at /.well-known/openid-configuration.',
                    impact='Reveals authorization endpoints, token endpoints, and supported scopes '
                           'which can be used to craft targeted OAuth attacks.',
                    remediation='Restrict access to /.well-known/openid-configuration if not required, '
                                'or ensure no sensitive endpoints are exposed.',
                    cwe='CWE-200',
                    cvss=2.0,
                    affected_url=url,
                    evidence=f'HTTP {resp.status_code}: {resp.text[:300]}',
                ))
        return found

    # ── WSTG-INFO-02 ──────────────────────────────────────────────────────────

    def _test_server_fingerprint(self, url: str):
        """Detect overly verbose server/technology banners in HTTP headers."""
        resp = self._make_request('GET', url)
        if not resp:
            return None

        leaks = {}
        for header in FINGERPRINT_HEADERS:
            val = resp.headers.get(header)
            if val:
                leaks[header] = val

        if not leaks:
            return None

        # Only flag if version numbers are present (more risky)
        version_re = re.compile(r'\d+\.\d+')
        versioned = {k: v for k, v in leaks.items() if version_re.search(v)}
        if not versioned:
            return None

        evidence = '\n'.join(f'{k}: {v}' for k, v in versioned.items())
        return self._build_vuln(
            name='Verbose Server Version Disclosure in HTTP Headers',
            severity='low',
            category='WSTG-INFO-02: Web Server Fingerprinting',
            description='The web server discloses its software name and version in HTTP '
                        'response headers, enabling targeted attack planning.',
            impact='Attackers can identify unpatched server software and use known CVEs.',
            remediation='Remove or redact version information from Server, X-Powered-By, and '
                        'similar headers. Use security headers like `Server: Web Server`.',
            cwe='CWE-200',
            cvss=3.1,
            affected_url=url,
            evidence=evidence,
        )

    # ── WSTG-INFO-05 ──────────────────────────────────────────────────────────

    def _test_entrypoints(self, page) -> list:
        """Map application entry points: forms, API-like URLs, hidden inputs."""
        found = []
        body = getattr(page, 'body', '') or ''

        # Detect API-like paths in page source that aren't on standard ports/paths
        api_hints = re.findall(r'(?:href|src|action|data-url|endpoint)\s*=\s*["\']([^"\']+/api/[^"\']*)["\']',
                               body, re.IGNORECASE)
        if api_hints:
            found.append(self._build_vuln(
                name='API Endpoints Enumerated from Page Source',
                severity='info',
                category='WSTG-INFO-05: Application Entry Points',
                description='API endpoints were discovered in the page HTML source code. '
                            'Exposing internal API paths increases the attack surface.',
                impact='Attackers can directly probe discovered API endpoints for authentication '
                       'bypass, IDOR, or injection vulnerabilities.',
                remediation='Avoid hardcoding internal API paths in frontend HTML. '
                            'Use indirect references and ensure all endpoints enforce authentication.',
                cwe='CWE-200',
                cvss=2.6,
                affected_url=page.url,
                evidence='API paths found in source: ' + ', '.join(api_hints[:10]),
            ))

        # Detect hidden form fields that could be tampered
        hidden_fields = re.findall(
            r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
            body, re.IGNORECASE,
        )
        # Also match reversed attribute order
        hidden_fields += re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\']',
            body, re.IGNORECASE,
        )
        sensitive_hidden = [f for f in hidden_fields
                            if any(k in f.lower() for k in ('price', 'amount', 'role',
                                                             'admin', 'uid', 'user_id',
                                                             'account', 'id'))]
        if sensitive_hidden:
            found.append(self._build_vuln(
                name='Sensitive Hidden Form Fields Detected',
                severity='medium',
                category='WSTG-INFO-05: Application Entry Points',
                description='HTML forms contain hidden fields with potentially security-sensitive '
                            'names (e.g., price, role, user_id). These may be tampered by attackers.',
                impact='Hidden field manipulation can lead to privilege escalation, price '
                       'tampering, or unauthorized access.',
                remediation='Validate all hidden field values server-side. Never trust client-supplied '
                            'values for role, price, or identifier fields.',
                cwe='CWE-472',
                cvss=5.4,
                affected_url=page.url,
                evidence='Suspicious hidden fields: ' + ', '.join(sensitive_hidden[:10]),
            ))

        return found

    # ── WSTG-INFO-01 ──────────────────────────────────────────────────────────

    def _test_robots_disclosure(self, base: str):
        """Check robots.txt for disallowed paths that reveal sensitive areas."""
        url = base + '/robots.txt'
        resp = self._make_request('GET', url)
        if not resp or resp.status_code != 200:
            return None

        disallowed = DISALLOW_PATTERN.findall(resp.text)
        sensitive_keywords = ['admin', 'api', 'internal', 'config', 'backup',
                               'private', 'secret', 'dev', 'staging', 'test']
        sensitive_paths = [p.strip() for p in disallowed
                           if any(k in p.lower() for k in sensitive_keywords)
                           and p.strip() not in ('/', '')]

        if not sensitive_paths:
            return None

        return self._build_vuln(
            name='robots.txt Discloses Sensitive Application Paths',
            severity='low',
            category='WSTG-INFO-01: Search Engine Discovery',
            description='The robots.txt file contains Disallow entries pointing to sensitive '
                        'application directories (admin panels, API paths, internal tools). '
                        'Although intended to suppress search engine indexing, these entries '
                        'serve as a roadmap for attackers.',
            impact='Attackers can enumerate hidden endpoints directly from robots.txt, '
                   'bypassing the intended obscurity.',
            remediation='Avoid listing sensitive paths in robots.txt. Use authentication, '
                        'proper access controls, and X-Robots-Tag headers instead.',
            cwe='CWE-200',
            cvss=3.1,
            affected_url=url,
            evidence='Sensitive Disallow entries: ' + ', '.join(sensitive_paths[:10]),
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _base_url(self, url: str) -> str:
        p = urlparse(url)
        return f'{p.scheme}://{p.netloc}'

    def _is_same_origin(self, base: str, location: str) -> bool:
        if not location:
            return False
        if location.startswith('/'):
            return True
        return urlparse(location).netloc == urlparse(base).netloc
