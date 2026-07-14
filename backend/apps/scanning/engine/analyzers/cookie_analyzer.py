"""
CookieAnalyzer — Checks cookie security attributes.
Maps to OWASP A02:2021 Cryptographic Failures + A07:2021 Auth Failures.
"""
import logging
import requests

logger = logging.getLogger(__name__)


class CookieAnalyzer:
    """Analyze cookie security attributes."""

    def analyze(self, url: str) -> list:
        """Check cookies for security flags."""
        vulnerabilities = []

        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = requests.get(
                url, timeout=15, verify=False,
                headers={'User-Agent': 'SafeWeb AI Scanner/1.0'},
            )
        except Exception as e:
            logger.warning(f'Failed to fetch cookies for {url}: {e}')
            return vulnerabilities

        for cookie in response.cookies:
            issues = []

            # Check Secure flag
            if not cookie.secure:
                issues.append('Missing Secure flag')

            # Check HttpOnly flag (from Set-Cookie header)
            set_cookie_headers = response.headers.get('Set-Cookie', '')
            cookie_header = ''
            for header_val in response.headers.getlist('Set-Cookie') if hasattr(response.headers, 'getlist') else [set_cookie_headers]:
                if cookie.name in header_val:
                    cookie_header = header_val
                    break

            if cookie_header and 'httponly' not in cookie_header.lower():
                issues.append('Missing HttpOnly flag')

            if cookie_header and 'samesite' not in cookie_header.lower():
                issues.append('Missing SameSite attribute')

            if issues:
                vulnerabilities.append({
                    'name': f'Insecure Cookie: {cookie.name}',
                    'severity': 'medium' if 'Secure' in str(issues) else 'low',
                    'category': 'Security Misconfiguration',
                    'description': f'Cookie "{cookie.name}" has security issues: {", ".join(issues)}.',
                    'impact': 'Insecure cookies may be intercepted over HTTP, accessed via JavaScript (XSS), or sent in cross-site requests (CSRF).',
                    'remediation': f'Set the following flags on the cookie: {", ".join(issues).replace("Missing ", "")}. Example: Set-Cookie: {cookie.name}=value; Secure; HttpOnly; SameSite=Lax',
                    'cwe': 'CWE-614',
                    'cvss': 4.3,
                    'affected_url': url,
                    'evidence': f'Cookie: {cookie.name}, Issues: {", ".join(issues)}',
                })

        return vulnerabilities
