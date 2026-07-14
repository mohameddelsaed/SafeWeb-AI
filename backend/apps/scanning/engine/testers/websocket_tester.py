"""
WebSocketTester — WebSocket security testing.
OWASP A03:2021 — Injection.

Tests for: missing authentication, cross-site WebSocket hijacking (CSWSH),
injection via WebSocket messages, and insecure ws:// usage.
"""
import re
import logging
from urllib.parse import urlparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)


class WebSocketTester(BaseTester):
    """Test for WebSocket security vulnerabilities."""

    TESTER_NAME = 'WebSocket'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Check for WebSocket endpoints in page source
        ws_endpoints = self._find_ws_endpoints(page)

        for endpoint in ws_endpoints:
            # Check for insecure ws:// (no TLS)
            vuln = self._check_insecure_ws(endpoint, page.url)
            if vuln:
                vulnerabilities.append(vuln)

            # Test CSWSH (Cross-Site WebSocket Hijacking)
            if depth in ('medium', 'deep'):
                vuln = self._test_cswsh(endpoint, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # Check for missing Origin validation
        if ws_endpoints and depth in ('medium', 'deep'):
            vuln = self._check_origin_validation(ws_endpoints[0], page.url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _find_ws_endpoints(self, page):
        """Find WebSocket endpoint URLs in the page source."""
        endpoints = []
        body = page.body or ''

        # Look for WebSocket constructor calls
        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'wss?://[^\s"\'<>]+',
            r'\.connect\s*\(\s*["\']([^"\']+)["\']',
        ]

        for pattern in ws_patterns:
            matches = re.findall(pattern, body)
            for match in matches:
                if match.startswith('ws://') or match.startswith('wss://'):
                    endpoints.append(match)
                elif '://' not in match and '/ws' in match.lower():
                    # Relative WebSocket path
                    parsed = urlparse(page.url)
                    scheme = 'wss' if parsed.scheme == 'https' else 'ws'
                    endpoints.append(f'{scheme}://{parsed.netloc}{match}')

        return list(set(endpoints))[:5]

    def _check_insecure_ws(self, endpoint, page_url):
        """Check if WebSocket uses unencrypted ws:// protocol."""
        if endpoint.startswith('ws://'):
            return self._build_vuln(
                name=f'Insecure WebSocket (ws://): {endpoint}',
                severity='medium',
                category='WebSocket Security',
                description=f'The WebSocket endpoint "{endpoint}" uses unencrypted ws:// protocol.',
                impact='WebSocket traffic can be intercepted, modified, or injected by '
                      'network attackers (man-in-the-middle).',
                remediation='Use wss:// (WebSocket Secure) for all WebSocket connections. '
                           'Ensure the web server is configured with valid TLS certificates.',
                cwe='CWE-319',
                cvss=5.3,
                affected_url=page_url,
                evidence=f'WebSocket endpoint: {endpoint} (unencrypted)',
            )
        return None

    def _test_cswsh(self, endpoint, page_url):
        """Test for Cross-Site WebSocket Hijacking.

        Attempt WebSocket connection with a cross-origin Origin header.
        If accepted, the endpoint is vulnerable to CSWSH.
        """
        try:
            import websocket
        except ImportError:
            logger.debug('websocket-client not installed, skipping CSWSH test')
            return None

        cross_origin = 'http://evil-attacker.com'

        try:
            ws = websocket.create_connection(
                endpoint,
                timeout=5,
                origin=cross_origin,
                header=['Sec-WebSocket-Protocol: chat'],
            )
            ws.close()

            return self._build_vuln(
                name=f'Cross-Site WebSocket Hijacking: {endpoint}',
                severity='high',
                category='WebSocket Security',
                description=f'The WebSocket endpoint accepted a connection with a cross-origin '
                           f'Origin header ({cross_origin}), enabling CSWSH attacks.',
                impact='Attackers can create malicious web pages that hijack authenticated '
                      'WebSocket connections, reading messages and sending commands as the victim.',
                remediation='Validate the Origin header on WebSocket upgrade requests. '
                           'Only accept connections from trusted origins. '
                           'Implement CSRF tokens in the WebSocket handshake.',
                cwe='CWE-346',
                cvss=8.1,
                affected_url=page_url,
                evidence=f'Endpoint: {endpoint}\nAccepted cross-origin: {cross_origin}',
            )
        except Exception:
            return None

    def _check_origin_validation(self, endpoint, page_url):
        """Check if the WebSocket endpoint validates Origin header."""
        try:
            import websocket
        except ImportError:
            return None

        # Try with no Origin header
        try:
            ws = websocket.create_connection(endpoint, timeout=5)
            ws.close()

            return self._build_vuln(
                name=f'WebSocket Missing Origin Validation: {endpoint}',
                severity='medium',
                category='WebSocket Security',
                description='The WebSocket endpoint accepts connections without an Origin header, '
                           'suggesting missing origin validation.',
                impact='Connections from any origin are accepted, facilitating CSWSH.',
                remediation='Require and validate the Origin header for all WebSocket connections.',
                cwe='CWE-346',
                cvss=5.3,
                affected_url=page_url,
                evidence='WebSocket accepted connection without Origin header.',
            )
        except Exception:
            return None
