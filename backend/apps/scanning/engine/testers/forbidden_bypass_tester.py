"""
Forbidden Bypass Tester — Detects 403/401 access-control bypass vectors.

Wraps the ForbiddenBypassEngine into the BaseTester interface so it
participates in the standard scan pipeline.
"""
import logging

from apps.scanning.engine.testers.base_tester import BaseTester
from apps.scanning.engine.bypass.forbidden_bypass import ForbiddenBypassEngine

logger = logging.getLogger(__name__)


class ForbiddenBypassTester(BaseTester):
    """Test for 403/401 bypass vulnerabilities using multiple techniques."""

    TESTER_NAME = '403/401 Bypass'

    def __init__(self):
        super().__init__()
        self._engine = ForbiddenBypassEngine()

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        status_code = getattr(page, 'status_code', 200)

        # Only engage on blocked responses
        if status_code not in (401, 403):
            return vulns

        # Run the bypass engine
        bypasses = self._engine.run(url, original_status_code=status_code, depth=depth)

        if not bypasses:
            return vulns

        # Group bypasses by technique
        techniques_found = {}
        for bp in bypasses:
            tech = bp['technique']
            if tech not in techniques_found:
                techniques_found[tech] = bp

        for tech, bp in techniques_found.items():
            vuln = self._build_bypass_vuln(bp, url, status_code)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Vuln builders ────────────────────────────────────────────────────────

    _TECHNIQUE_META = {
        'path_manipulation': {
            'name': 'Path Manipulation Bypass',
            'severity': 'high',
            'description': (
                'The server\'s access control for this URL can be bypassed '
                'by manipulating the URL path (trailing slash, encoding, '
                'case change, etc.).'
            ),
            'impact': 'Full access to restricted resources, admin panel exposure',
            'remediation': (
                'Normalize paths before authorization checks. Use a web '
                'application firewall that canonicalises URLs. Deny by '
                'default and allowlist known paths.'
            ),
            'cwe': 'CWE-863',
            'cvss': 7.5,
        },
        'method_bypass': {
            'name': 'HTTP Method Bypass',
            'severity': 'high',
            'description': (
                'Access control on this resource only applies to specific '
                'HTTP methods. A different method returns the protected '
                'content.'
            ),
            'impact': 'Bypass authentication/authorization via alternative HTTP method',
            'remediation': (
                'Enforce access control on all HTTP methods. Deny unknown '
                'methods. Configure the web server to only allow required '
                'methods per endpoint.'
            ),
            'cwe': 'CWE-287',
            'cvss': 7.5,
        },
        'header_bypass': {
            'name': 'Header-Based Access Control Bypass',
            'severity': 'critical',
            'description': (
                'Access control can be bypassed by adding specific HTTP '
                'headers (IP spoofing, URL rewrite, etc.) that the '
                'reverse proxy or application trusts.'
            ),
            'impact': 'Complete access control bypass, admin access',
            'remediation': (
                'Do not trust client-supplied IP headers for authorization. '
                'Validate headers at the reverse proxy level. Use proper '
                'authentication instead of IP-based access control.'
            ),
            'cwe': 'CWE-290',
            'cvss': 9.1,
        },
        'protocol_bypass': {
            'name': 'Protocol Manipulation Bypass',
            'severity': 'medium',
            'description': (
                'Access control can be bypassed by manipulating protocol '
                'headers (X-Forwarded-Proto, port, connection type).'
            ),
            'impact': 'Access to restricted resources via protocol confusion',
            'remediation': (
                'Do not rely on protocol headers for access decisions. '
                'Enforce HTTPS at the transport layer.'
            ),
            'cwe': 'CWE-863',
            'cvss': 5.3,
        },
        'method_override': {
            'name': 'Method Override Bypass',
            'severity': 'high',
            'description': (
                'The server respects method-override headers or _method '
                'parameters, allowing attackers to change the effective '
                'HTTP method and bypass access controls.'
            ),
            'impact': 'Access control bypass via method spoofing',
            'remediation': (
                'Disable method override headers in production. If needed, '
                'enforce authorization after method resolution.'
            ),
            'cwe': 'CWE-287',
            'cvss': 7.5,
        },
    }

    def _build_bypass_vuln(self, bypass: dict, url: str, orig_status: int):
        """Convert a bypass result dict into a vulnerability dict."""
        tech = bypass['technique']
        meta = self._TECHNIQUE_META.get(tech)
        if not meta:
            return None

        return self._build_vuln(
            name=meta['name'],
            severity=meta['severity'],
            category='Broken Access Control',
            description=(
                f'{meta["description"]} '
                f'Original status: HTTP {orig_status}. '
                f'Bypass: {bypass["variant"]} → HTTP {bypass["status_code"]}.'
            ),
            impact=meta['impact'],
            remediation=meta['remediation'],
            cwe=meta['cwe'],
            cvss=meta['cvss'],
            affected_url=bypass.get('url', url),
            evidence=bypass.get('evidence', ''),
        )
