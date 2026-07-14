"""
VHost Tester — Detects virtual host enumeration vulnerabilities.

Covers:
  - Host header brute-force for vhosts
  - Default vhost detection
  - Wildcard vhost detection
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Common vhost prefixes to test ────────────────────────────────────────────
VHOST_PREFIXES = [
    'admin', 'staging', 'dev', 'test', 'beta', 'internal',
    'api', 'portal', 'dashboard', 'mail', 'webmail',
    'intranet', 'vpn', 'git', 'jenkins', 'ci', 'cd',
    'monitoring', 'grafana', 'kibana', 'elastic',
    'phpmyadmin', 'mysql', 'postgres', 'redis',
    'backup', 'old', 'legacy', 'new', 'www2',
]

# ── Indicators of a real (non-default) vhost response ────────────────────────
REAL_VHOST_INDICATORS = [
    re.compile(r'<title>', re.IGNORECASE),
    re.compile(r'<form', re.IGNORECASE),
    re.compile(r'login|sign.?in|dashboard', re.IGNORECASE),
]

# ── Default/error page indicators ────────────────────────────────────────────
DEFAULT_PAGE_INDICATORS = [
    re.compile(r'welcome to nginx', re.IGNORECASE),
    re.compile(r'apache.*default.*page', re.IGNORECASE),
    re.compile(r'it works!', re.IGNORECASE),
    re.compile(r'iis.*windows', re.IGNORECASE),
    re.compile(r'default web site', re.IGNORECASE),
    re.compile(r'test page.*apache', re.IGNORECASE),
]


class VHostTester(BaseTester):
    """Test for virtual host enumeration vulnerabilities."""

    TESTER_NAME = 'Virtual Host Enumeration'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        getattr(page, 'headers', {}) or {}

        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        if not hostname:
            return vulns

        # 1. Check for default vhost
        vuln = self._check_default_vhost(url, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Test wildcard vhost
        vuln = self._test_wildcard_vhost(url, hostname, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'deep':
            # 3. Enumerate common vhost prefixes
            vuln = self._enumerate_vhosts(url, hostname, body)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_default_vhost(self, url: str, body: str):
        """Check if the page is a default web server page."""
        for pattern in DEFAULT_PAGE_INDICATORS:
            if pattern.search(body):
                return self._build_vuln(
                    name='Default Virtual Host Page',
                    severity='low',
                    category='Security Misconfiguration',
                    description=(
                        'The server returns a default web server page, '
                        'indicating the virtual host is not configured or '
                        'is the default catch-all vhost.'
                    ),
                    impact='Information disclosure, server identification',
                    remediation=(
                        'Configure a custom default page. '
                        'Disable or redirect default vhost responses.'
                    ),
                    cwe='CWE-200',
                    cvss=3.7,
                    affected_url=url,
                    evidence=f'Default page indicator: {pattern.pattern}',
                )
        return None

    def _test_wildcard_vhost(self, url: str, hostname: str, orig_body: str):
        """Test if the server accepts wildcard/arbitrary vhosts."""
        random_host = 'nonexistent-subdomain-xyzzy42.' + hostname
        try:
            resp = self._make_request(
                'GET', url,
                headers={'Host': random_host},
            )
            if not resp:
                return None

            resp_body = getattr(resp, 'text', '')

            # Wildcard: random host returns same content as original
            if (resp.status_code == 200
                    and len(resp_body) > 100
                    and any(p.search(resp_body) for p in REAL_VHOST_INDICATORS)):
                return self._build_vuln(
                    name='Wildcard Virtual Host',
                    severity='low',
                    category='Security Misconfiguration',
                    description=(
                        f'The server responds with a real page when the Host '
                        f'header is set to "{random_host}". This indicates '
                        'wildcard vhost configuration, which may expose '
                        'internal applications.'
                    ),
                    impact='Vhost enumeration, potential access to internal apps',
                    remediation=(
                        'Configure explicit vhost entries. '
                        'Return 404/403 for unknown Host headers.'
                    ),
                    cwe='CWE-200',
                    cvss=4.3,
                    affected_url=url,
                    evidence=f'Wildcard host accepted: {random_host}',
                )
        except Exception:
            pass
        return None

    def _enumerate_vhosts(self, url: str, hostname: str, orig_body: str):
        """Enumerate common vhost prefixes."""
        # Extract base domain
        parts = hostname.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = hostname

        found_vhosts = []
        for prefix in VHOST_PREFIXES[:10]:
            test_host = f'{prefix}.{base_domain}'
            if test_host == hostname:
                continue

            try:
                resp = self._make_request(
                    'GET', url,
                    headers={'Host': test_host},
                )
                if not resp:
                    continue

                resp_body = getattr(resp, 'text', '')

                # Real vhost: different from original and has content
                if (resp.status_code == 200
                        and len(resp_body) > 100
                        and any(p.search(resp_body) for p in REAL_VHOST_INDICATORS)
                        and abs(len(resp_body) - len(orig_body)) > 200):
                    found_vhosts.append(test_host)
                    if len(found_vhosts) >= 3:
                        break
            except Exception:
                continue

        if found_vhosts:
            return self._build_vuln(
                name='Hidden Virtual Host Discovered',
                severity='medium',
                category='Security Misconfiguration',
                description=(
                    f'Virtual host enumeration discovered the following '
                    f'hidden hosts: {", ".join(found_vhosts)}. These may '
                    'expose internal or administrative applications.'
                ),
                impact='Access to internal applications, admin panels, dev environments',
                remediation=(
                    'Restrict vhost access via network controls. '
                    'Do not expose internal vhosts on public-facing servers.'
                ),
                cwe='CWE-200',
                cvss=5.3,
                affected_url=url,
                evidence=f'Discovered vhosts: {", ".join(found_vhosts)}',
            )
        return None
