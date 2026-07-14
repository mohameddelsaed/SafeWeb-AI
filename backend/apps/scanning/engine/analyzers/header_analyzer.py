"""
HeaderAnalyzer — Checks for missing or misconfigured security headers.
Maps to OWASP A05:2021 Security Misconfiguration.
"""
import logging
import requests

logger = logging.getLogger(__name__)

REQUIRED_HEADERS = {
    'X-Frame-Options': {
        'expected': ['DENY', 'SAMEORIGIN'],
        'severity': 'medium',
        'cvss': 4.3,
        'cwe': 'CWE-1021',
        'category': 'Security Misconfiguration',
        'description': 'The X-Frame-Options header is missing, which may allow clickjacking attacks.',
        'impact': 'An attacker could embed this page in an iframe and trick users into clicking hidden elements.',
        'remediation': 'Add the header: X-Frame-Options: DENY or SAMEORIGIN',
    },
    'X-Content-Type-Options': {
        'expected': ['nosniff'],
        'severity': 'low',
        'cvss': 3.1,
        'cwe': 'CWE-16',
        'category': 'Security Misconfiguration',
        'description': 'The X-Content-Type-Options header is missing, allowing MIME-type sniffing.',
        'impact': 'Browsers may interpret files as a different MIME type, potentially executing malicious content.',
        'remediation': 'Add the header: X-Content-Type-Options: nosniff',
    },
    'Strict-Transport-Security': {
        'expected': None,  # Just check presence
        'severity': 'high',
        'cvss': 7.4,
        'cwe': 'CWE-319',
        'category': 'Cryptographic Failures',
        'description': 'HTTP Strict Transport Security (HSTS) header is missing.',
        'impact': 'Users may connect over insecure HTTP, exposing traffic to interception and man-in-the-middle attacks.',
        'remediation': 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    'Content-Security-Policy': {
        'expected': None,
        'severity': 'medium',
        'cvss': 5.4,
        'cwe': 'CWE-79',
        'category': 'Security Misconfiguration',
        'description': 'Content Security Policy (CSP) header is not set.',
        'impact': 'Without CSP, the application may be more vulnerable to XSS and data injection attacks.',
        'remediation': "Add a Content-Security-Policy header, e.g.: default-src 'self'; script-src 'self'",
    },
    'Referrer-Policy': {
        'expected': None,
        'severity': 'low',
        'cvss': 3.1,
        'cwe': 'CWE-200',
        'category': 'Security Misconfiguration',
        'description': 'The Referrer-Policy header is missing.',
        'impact': 'Sensitive URL information may be leaked to third-party sites through the Referer header.',
        'remediation': 'Add the header: Referrer-Policy: strict-origin-when-cross-origin',
    },
    'Permissions-Policy': {
        'expected': None,
        'severity': 'low',
        'cvss': 2.6,
        'cwe': 'CWE-16',
        'category': 'Security Misconfiguration',
        'description': 'The Permissions-Policy (formerly Feature-Policy) header is not set.',
        'impact': 'Browser features like camera, microphone, and geolocation may be accessible to embedded content.',
        'remediation': 'Add a Permissions-Policy header to restrict browser feature access.',
    },
}

# Headers that should NOT be present (information disclosure)
DISCLOSURE_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']


class HeaderAnalyzer:
    """Analyze HTTP security headers."""

    def analyze(self, url: str) -> list:
        """Analyze security headers of the target URL."""
        vulnerabilities = []

        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = requests.get(
                url, timeout=15, verify=False,
                headers={'User-Agent': 'SafeWeb AI Scanner/1.0'},
            )
        except Exception as e:
            logger.warning(f'Failed to fetch headers for {url}: {e}')
            return vulnerabilities

        headers = response.headers

        # Check for missing security headers
        for header_name, config in REQUIRED_HEADERS.items():
            if header_name not in headers:
                vulnerabilities.append({
                    'name': f'Missing {header_name} Header',
                    'severity': config['severity'],
                    'category': config['category'],
                    'description': config['description'],
                    'impact': config['impact'],
                    'remediation': config['remediation'],
                    'cwe': config['cwe'],
                    'cvss': config['cvss'],
                    'affected_url': url,
                    'evidence': f'Response headers do not include {header_name}.',
                })

        # Check for information disclosure headers
        for header_name in DISCLOSURE_HEADERS:
            if header_name in headers:
                vulnerabilities.append({
                    'name': f'Server Version Disclosure via {header_name}',
                    'severity': 'low',
                    'category': 'Security Misconfiguration',
                    'description': f'The {header_name} header reveals server technology: {headers[header_name]}',
                    'impact': 'Attackers can use this information to target known vulnerabilities in the specific software version.',
                    'remediation': f'Remove or suppress the {header_name} header in your server configuration.',
                    'cwe': 'CWE-200',
                    'cvss': 2.6,
                    'affected_url': url,
                    'evidence': f'{header_name}: {headers[header_name]}',
                })

        return vulnerabilities
