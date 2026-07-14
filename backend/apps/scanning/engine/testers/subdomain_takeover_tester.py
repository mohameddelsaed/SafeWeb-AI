"""
SubdomainTakeoverTester — Subdomain Takeover detection.
OWASP A05:2021 — Security Misconfiguration.

Tests for: dangling CNAME records, cloud provider fingerprints,
unregistered services, and vulnerable third-party platforms.
"""
import re
import socket
import logging
from urllib.parse import urlparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Known vulnerable services — fingerprints indicating takeover potential
VULNERABLE_SERVICES = {
    'github': {
        'cname_patterns': ['github.io', 'github.com'],
        'fingerprints': ['There isn\'t a GitHub Pages site here', 'For root URLs'],
        'severity': 'high',
    },
    'heroku': {
        'cname_patterns': ['herokuapp.com', 'herokussl.com', 'herokudns.com'],
        'fingerprints': ['No such app', 'no-such-app', 'herokucdn.com/error-pages'],
        'severity': 'high',
    },
    'aws_s3': {
        'cname_patterns': ['s3.amazonaws.com', 's3-website', '.s3.'],
        'fingerprints': ['NoSuchBucket', 'The specified bucket does not exist'],
        'severity': 'critical',
    },
    'aws_cloudfront': {
        'cname_patterns': ['cloudfront.net'],
        'fingerprints': ['Bad request', 'ERROR: The request could not be satisfied'],
        'severity': 'high',
    },
    'azure': {
        'cname_patterns': ['azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com',
                          'azurefd.net', 'blob.core.windows.net', 'azure-api.net',
                          'azureedge.net', 'azurecontainer.io', 'trafficmanager.net'],
        'fingerprints': ['404 Web Site not found', 'This web app is stopped',
                        'The resource you are looking for has been removed'],
        'severity': 'high',
    },
    'shopify': {
        'cname_patterns': ['myshopify.com'],
        'fingerprints': ['Sorry, this shop is currently unavailable', 'Only one step left'],
        'severity': 'high',
    },
    'fastly': {
        'cname_patterns': ['fastly.net', 'fastlylb.net'],
        'fingerprints': ['Fastly error: unknown domain'],
        'severity': 'high',
    },
    'pantheon': {
        'cname_patterns': ['pantheonsite.io'],
        'fingerprints': ['404 error unknown site', 'The gods are wise'],
        'severity': 'high',
    },
    'netlify': {
        'cname_patterns': ['netlify.app', 'netlify.com'],
        'fingerprints': ['Not Found - Request ID'],
        'severity': 'high',
    },
    'zendesk': {
        'cname_patterns': ['zendesk.com'],
        'fingerprints': ['Help Center Closed', 'Oops, this help center no longer exists'],
        'severity': 'high',
    },
    'wordpress': {
        'cname_patterns': ['wordpress.com'],
        'fingerprints': ['Do you want to register'],
        'severity': 'high',
    },
    'surge': {
        'cname_patterns': ['surge.sh'],
        'fingerprints': ['project not found'],
        'severity': 'medium',
    },
    'bitbucket': {
        'cname_patterns': ['bitbucket.io'],
        'fingerprints': ['Repository not found'],
        'severity': 'high',
    },
    'ghost': {
        'cname_patterns': ['ghost.io'],
        'fingerprints': ['The thing you were looking for is no longer here'],
        'severity': 'high',
    },
    'tumblr': {
        'cname_patterns': ['tumblr.com'],
        'fingerprints': ['Whatever you were looking for doesn\'t currently exist at this address',
                        "There's nothing here"],
        'severity': 'medium',
    },
}


class SubdomainTakeoverTester(BaseTester):
    """Test for subdomain takeover vulnerabilities."""

    TESTER_NAME = 'Subdomain Takeover'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # 1. Check if current domain has takeover indicators
        vuln = self._check_current_domain(page)
        if vuln:
            vulnerabilities.append(vuln)

        # 2. Find and check linked subdomains
        if depth in ('medium', 'deep'):
            vulns = self._check_linked_subdomains(page, depth)
            vulnerabilities.extend(vulns)

        # 3. DNS resolution check (deep)
        if depth == 'deep':
            vuln = self._check_dns_dangling(page)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_current_domain(self, page) -> object:
        """Check the current page for takeover fingerprints."""
        try:
            response = self._make_request('GET', page.url)
        except Exception:
            return None

        if not response:
            return None

        body = response.text
        parsed = urlparse(page.url)
        hostname = parsed.hostname or ''

        for service, info in VULNERABLE_SERVICES.items():
            # Check if hostname matches known CNAME patterns
            if any(pattern in hostname for pattern in info['cname_patterns']):
                # Check for telltale fingerprints
                if any(fp.lower() in body.lower() for fp in info['fingerprints']):
                    return self._build_vuln(
                        name=f'Potential Subdomain Takeover ({service})',
                        severity=info['severity'],
                        category='Subdomain Takeover',
                        description=f'The domain "{hostname}" points to {service} but displays '
                                   f'an unclaimed resource error. This indicates the external '
                                   f'service is no longer configured, allowing an attacker to '
                                   f'claim the service and serve content on this domain.',
                        impact='Attackers can register the unclaimed service and serve malicious '
                              'content on the victim\'s domain, enabling phishing, cookie theft, '
                              'and reputation damage.',
                        remediation=f'Remove the DNS CNAME record pointing to {service}. '
                                   f'Alternatively, reclaim the resource on the {service} platform.',
                        cwe='CWE-284',
                        cvss=8.6 if info['severity'] == 'critical' else 7.5,
                        affected_url=page.url,
                        evidence=f'Domain: {hostname}\nService: {service}\n'
                                f'Fingerprint detected in response.',
                    )

        return None

    def _check_linked_subdomains(self, page, depth: str) -> list:
        """Find and check subdomains linked from the page."""
        vulnerabilities = []
        body = page.body or ''
        parsed = urlparse(page.url)
        main_domain = self._get_root_domain(parsed.hostname or '')

        # Extract all linked hostnames
        href_pattern = re.findall(r'(?:href|src|action)\s*=\s*["\']https?://([^/\'"]+)', body, re.IGNORECASE)
        linked_hosts = set(href_pattern)

        # Filter to subdomains of the main domain
        subdomains = {h for h in linked_hosts
                      if h != parsed.hostname and main_domain and h.endswith(f'.{main_domain}')}

        max_checks = 5 if depth == 'medium' else 15
        checked = 0

        for subdomain in subdomains:
            if checked >= max_checks:
                break

            test_url = f'https://{subdomain}'
            try:
                response = self._make_request('GET', test_url, timeout=5)
            except Exception:
                # Connection failure could indicate dangling DNS
                try:
                    socket.getaddrinfo(subdomain, None)
                    # DNS resolves but connection fails — suspicious
                    vulnerabilities.append(self._build_vuln(
                        name=f'Potential Dangling Subdomain: {subdomain}',
                        severity='medium',
                        category='Subdomain Takeover',
                        description=f'The subdomain "{subdomain}" resolves in DNS but the '
                                   f'service is unreachable. This may indicate a dangling record.',
                        impact='If the DNS points to an external service, an attacker may be '
                              'able to claim it.',
                        remediation='Review and clean up DNS records. Remove entries pointing to '
                                   'decommissioned services.',
                        cwe='CWE-284',
                        cvss=5.3,
                        affected_url=test_url,
                        evidence=f'Subdomain: {subdomain}\nDNS: Resolves\nHTTPS: Unreachable',
                    ))
                except socket.gaierror:
                    pass  # DNS doesn't resolve — not takeover-vulnerable
                checked += 1
                continue

            if not response:
                checked += 1
                continue

            body = response.text
            for service, info in VULNERABLE_SERVICES.items():
                if any(fp.lower() in body.lower() for fp in info['fingerprints']):
                    vulnerabilities.append(self._build_vuln(
                        name=f'Subdomain Takeover: {subdomain} ({service})',
                        severity=info['severity'],
                        category='Subdomain Takeover',
                        description=f'The linked subdomain "{subdomain}" points to {service} '
                                   f'but displays an unclaimed resource error.',
                        impact='Attackers can claim the subdomain and serve malicious content, '
                              'steal cookies set on the parent domain, or conduct phishing.',
                        remediation=f'Remove the CNAME for {subdomain} or reclaim the '
                                   f'{service} resource.',
                        cwe='CWE-284',
                        cvss=7.5,
                        affected_url=test_url,
                        evidence=f'Subdomain: {subdomain}\nService: {service}',
                    ))
                    break

            checked += 1

        return vulnerabilities

    def _check_dns_dangling(self, page) -> object:
        """Check if the domain has a CNAME to a known service with NXDOMAIN."""
        parsed = urlparse(page.url)
        hostname = parsed.hostname or ''

        try:
            # Try to resolve CNAME
            socket.getaddrinfo(hostname, None)
            # If we get here, DNS resolves — check if it matches known services
            for service, info in VULNERABLE_SERVICES.items():
                for pattern in info['cname_patterns']:
                    if pattern in hostname:
                        # Already checked via _check_current_domain
                        return None
        except socket.gaierror:
            # NXDOMAIN — domain doesn't resolve
            return self._build_vuln(
                name='NXDOMAIN on Scanned Domain',
                severity='info',
                category='Subdomain Takeover',
                description=f'The scanned domain "{hostname}" does not resolve in DNS (NXDOMAIN).',
                impact='If this domain previously resolved to an external service, it may be '
                      'vulnerable to takeover.',
                remediation='Verify DNS configuration. Remove stale DNS records.',
                cwe='CWE-284',
                cvss=0.0,
                affected_url=page.url,
                evidence=f'Domain: {hostname}\nDNS: NXDOMAIN',
            )

        return None

    def _get_root_domain(self, hostname: str) -> str:
        """Extract root domain from hostname."""
        parts = hostname.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname
