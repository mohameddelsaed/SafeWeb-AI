"""
DNS Rebinding Tester — Detects DNS rebinding attack vectors.

Covers:
  - Time-based rebinding to internal services
  - Rebind to cloud metadata endpoints
  - Detection of missing Host header validation
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Cloud metadata endpoints targeted by DNS rebinding ───────────────────────
METADATA_ENDPOINTS = [
    ('AWS', '169.254.169.254', '/latest/meta-data/'),
    ('GCP', '169.254.169.254', '/computeMetadata/v1/'),
    ('Azure', '169.254.169.254', '/metadata/instance?api-version=2021-02-01'),
    ('DigitalOcean', '169.254.169.254', '/metadata/v1/'),
]

# ── Internal IP ranges ──────────────────────────────────────────────────────
INTERNAL_IP_RE = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|169\.254\.\d{1,3}\.\d{1,3})\b'
)

# ── DNS rebinding host header payloads ───────────────────────────────────────
REBIND_HOST_PAYLOADS = [
    '127.0.0.1',
    'localhost',
    '169.254.169.254',
    '0.0.0.0',
    '[::1]',
    '0x7f000001',          # Hex IP for 127.0.0.1
    '2130706433',          # Decimal IP for 127.0.0.1
    '0177.0.0.1',          # Octal
    '127.0.0.1.nip.io',   # nip.io DNS rebinding service
]

# ── Indicators that host validation is missing ───────────────────────────────
HOST_ACCEPT_INDICATORS = [
    re.compile(r'<title>', re.IGNORECASE),  # Normal page rendered
]


class DNSRebindingTester(BaseTester):
    """Test for DNS rebinding attack vulnerabilities."""

    TESTER_NAME = 'DNS Rebinding'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        getattr(page, 'headers', {}) or {}

        # 1. Check for internal IP/metadata references in body
        vuln = self._check_internal_ip_exposure(url, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 2. Test host header validation (key for DNS rebinding)
        vuln = self._test_host_header_validation(url, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'deep':
            # 3. Test for metadata endpoint accessibility indicators
            vuln = self._check_metadata_indicators(url, body, recon_data)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_internal_ip_exposure(self, url: str, body: str):
        """Check for internal IP addresses or metadata URLs in page body."""
        matches = INTERNAL_IP_RE.findall(body)
        if matches:
            unique = list(set(matches))[:5]
            return self._build_vuln(
                name='Internal IP Address Exposure',
                severity='low',
                category='Information Disclosure',
                description=(
                    'Internal IP addresses detected in the page body. '
                    'This reveals internal network structure and may be '
                    'targeted via DNS rebinding.'
                ),
                impact='Network topology disclosure, DNS rebinding attack target identification',
                remediation=(
                    'Remove internal IP addresses from public responses. '
                    'Use hostnames instead of IPs for internal services.'
                ),
                cwe='CWE-200',
                cvss=3.7,
                affected_url=url,
                evidence=f'Internal IPs found: {", ".join(unique)}',
            )
        return None

    def _test_host_header_validation(self, url: str, orig_body: str):
        """Test if the server accepts arbitrary Host headers."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        original_host = parsed.hostname

        for rebind_host in REBIND_HOST_PAYLOADS[:4]:
            try:
                resp = self._make_request(
                    'GET', url,
                    headers={'Host': rebind_host},
                )
                if not resp:
                    continue

                # If server accepts the evil host and returns a similar page
                if resp.status_code == 200:
                    resp_body = getattr(resp, 'text', '')
                    # Check if the response is a real page (not an error)
                    if (len(resp_body) > 100
                            and any(p.search(resp_body) for p in HOST_ACCEPT_INDICATORS)):
                        return self._build_vuln(
                            name='DNS Rebinding - Missing Host Validation',
                            severity='high',
                            category='Security Misconfiguration',
                            description=(
                                f'The server accepts requests with Host header '
                                f'set to "{rebind_host}" instead of the legitimate '
                                f'host "{original_host}". This enables DNS rebinding '
                                'attacks against internal services.'
                            ),
                            impact=(
                                'DNS rebinding to access internal services, '
                                'cloud metadata theft, SSRF via DNS rebinding'
                            ),
                            remediation=(
                                'Validate the Host header against a whitelist of '
                                'allowed hostnames. Return 400/403 for unknown hosts.'
                            ),
                            cwe='CWE-350',
                            cvss=7.5,
                            affected_url=url,
                            evidence=f'Server accepted Host: {rebind_host} (status {resp.status_code})',
                        )
            except Exception:
                continue
        return None

    def _check_metadata_indicators(self, url: str, body: str,
                                   recon_data: dict = None):
        """Check for cloud metadata endpoint access indicators."""
        cloud_info = self._get_cloud_info(recon_data) if recon_data else {}
        cloud_info.get('provider', '')

        # Check if body references metadata endpoint
        for provider, ip, path in METADATA_ENDPOINTS:
            if ip in body or path in body:
                return self._build_vuln(
                    name='Cloud Metadata Endpoint Reference',
                    severity='medium',
                    category='Security Misconfiguration',
                    description=(
                        f'{provider} cloud metadata endpoint ({ip}{path}) '
                        'is referenced in the page body. This may be exploitable '
                        'via DNS rebinding to access instance credentials.'
                    ),
                    impact='Cloud credential theft, privilege escalation via metadata',
                    remediation=(
                        f'Block access to {ip} from application code. '
                        'Use IMDSv2 (AWS) or equivalent token-based metadata access. '
                        'Implement network-level metadata endpoint protection.'
                    ),
                    cwe='CWE-918',
                    cvss=6.5,
                    affected_url=url,
                    evidence=f'{provider} metadata reference: {ip}{path}',
                )
        return None
