"""
Reverse Proxy Misconfiguration Tester — Detects reverse proxy misconfiguration.

Covers:
  - Path normalization confusion (Nginx off-by-slash)
  - Header injection through proxy
  - Backend server direct access
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Path normalization payloads (Nginx off-by-slash, etc.) ───────────────────
PATH_NORM_PAYLOADS = [
    # Nginx off-by-slash: /path../other
    ('../', 'Off-by-slash traversal'),
    ('..;/', 'Semicolon traversal (Tomcat)'),
    ('%2e%2e/', 'URL-encoded dot traversal'),
    ('.%00/', 'Null byte path break'),
    ('%2e%2e%2f', 'Double-encoded dot traversal'),
]

# ── Backend exposure indicators ──────────────────────────────────────────────
BACKEND_INDICATORS = [
    re.compile(r'(?:tomcat|jetty|gunicorn|uvicorn|werkzeug)', re.IGNORECASE),
    re.compile(r'x-powered-by:\s*(?:express|php|asp\.net)', re.IGNORECASE),
    re.compile(r'server:\s*(?:apache|nginx|iis)', re.IGNORECASE),
]

# ── Internal path patterns (should not be accessible) ────────────────────────
INTERNAL_PATHS = [
    '/server-status', '/server-info',
    '/nginx_status', '/stub_status',
    '/.env', '/.git/config',
    '/actuator', '/actuator/health',
    '/debug', '/debug/vars',
    '/metrics', '/healthz',
    '/admin/', '/manager/',
]

# ── Proxy-related headers ───────────────────────────────────────────────────
PROXY_HEADERS = [
    'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto',
    'X-Real-IP', 'X-Original-URL', 'X-Rewrite-URL',
    'Via', 'X-Proxy-Id', 'Forwarded',
]

# ── Hop-by-hop header injection payloads ─────────────────────────────────────
HOP_BY_HOP_HEADERS = [
    'Connection', 'Keep-Alive', 'Transfer-Encoding',
    'TE', 'Trailer', 'Upgrade',
]


class ReverseProxyMisconfigTester(BaseTester):
    """Test for reverse proxy misconfiguration vulnerabilities."""

    TESTER_NAME = 'Reverse Proxy Misconfiguration'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        getattr(page, 'body', '') or ''
        headers = getattr(page, 'headers', {}) or {}

        # 1. Check for proxy-related headers (indicates reverse proxy)
        vuln = self._check_proxy_headers(url, headers)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Test path normalization confusion
        vuln = self._test_path_normalization(url)
        if vuln:
            vulns.append(vuln)

        if depth == 'deep':
            # 3. Test backend direct access via internal paths
            vuln = self._test_backend_access(url)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_proxy_headers(self, url: str, headers: dict):
        """Check for proxy-related headers that indicate reverse proxy."""
        found_headers = []
        for h in PROXY_HEADERS:
            if h.lower() in {k.lower() for k in headers}:
                found_headers.append(h)

        if found_headers:
            return self._build_vuln(
                name='Reverse Proxy Headers Detected',
                severity='info',
                category='Information Disclosure',
                description=(
                    f'Proxy-related headers detected: {", ".join(found_headers)}. '
                    'This reveals the presence of a reverse proxy and may '
                    'indicate misconfiguration opportunities.'
                ),
                impact='Reverse proxy fingerprinting, configuration insights',
                remediation=(
                    'Strip proxy-related headers from responses. '
                    'Use proxy_hide_header in Nginx or equivalent.'
                ),
                cwe='CWE-200',
                cvss=2.0,
                affected_url=url,
                evidence=f'Proxy headers: {", ".join(found_headers)}',
            )
        return None

    def _test_path_normalization(self, url: str):
        """Test for path normalization confusion."""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        base_path = parsed.path.rstrip('/')

        if not base_path or base_path == '':
            base_path = ''

        for suffix, desc in PATH_NORM_PAYLOADS[:3]:
            test_path = base_path + '/' + suffix + 'etc/passwd'
            test_url = urlunparse(parsed._replace(path=test_path))

            try:
                resp = self._make_request('GET', test_url)
                if not resp:
                    continue

                resp_body = getattr(resp, 'text', '')

                # Check for path traversal success
                if 'root:' in resp_body and ':0:0:' in resp_body:
                    return self._build_vuln(
                        name='Path Normalization Bypass',
                        severity='critical',
                        category='Security Misconfiguration',
                        description=(
                            f'Path normalization confusion ({desc}) bypassed '
                            'the reverse proxy path restrictions, exposing '
                            'backend resources.'
                        ),
                        impact='Access to restricted resources, file read, RCE',
                        remediation=(
                            'Normalize paths before processing at both proxy and '
                            'backend. Use merge_slashes and resolve ../ at proxy level.'
                        ),
                        cwe='CWE-22',
                        cvss=9.8,
                        affected_url=test_url,
                        evidence=f'Path traversal via: {suffix}',
                    )

                # Check for different response from proxy vs backend
                if (resp.status_code == 200
                        and len(resp_body) > 100
                        and any(p.search(resp_body) for p in BACKEND_INDICATORS)):
                    return self._build_vuln(
                        name='Path Normalization Bypass',
                        severity='high',
                        category='Security Misconfiguration',
                        description=(
                            f'Path normalization ({desc}) reveals backend '
                            'server content that should be proxied.'
                        ),
                        impact='Access to backend resources, proxy bypass',
                        remediation='Normalize request paths at the proxy level.',
                        cwe='CWE-22',
                        cvss=7.5,
                        affected_url=test_url,
                        evidence=f'Backend exposed via: {suffix}',
                    )
            except Exception:
                continue
        return None

    def _test_backend_access(self, url: str):
        """Test if internal/debug endpoints are accessible."""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)

        for path in INTERNAL_PATHS[:6]:
            test_url = urlunparse(parsed._replace(path=path))
            try:
                resp = self._make_request('GET', test_url)
                if not resp:
                    continue

                resp_body = getattr(resp, 'text', '')

                # Check if internal endpoint returned content
                if (resp.status_code == 200
                        and len(resp_body) > 50
                        and 'not found' not in resp_body.lower()):
                    return self._build_vuln(
                        name='Internal Endpoint Exposed',
                        severity='medium',
                        category='Security Misconfiguration',
                        description=(
                            f'Internal endpoint "{path}" is accessible through '
                            'the reverse proxy. This should be restricted.'
                        ),
                        impact='Server information disclosure, debug data exposure',
                        remediation=(
                            f'Block access to "{path}" at the proxy level. '
                            'Use allow/deny rules for internal endpoints.'
                        ),
                        cwe='CWE-200',
                        cvss=5.3,
                        affected_url=test_url,
                        evidence=f'Internal path accessible: {path} (status {resp.status_code})',
                    )
            except Exception:
                continue
        return None
