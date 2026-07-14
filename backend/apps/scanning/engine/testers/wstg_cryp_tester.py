"""
WSTGCryptographyTester — OWASP WSTG-CRYP coverage.
Maps to: WSTG-CRYP-01 (Weak SSL/TLS), WSTG-CRYP-02 (Padding Oracle),
         WSTG-CRYP-03 (Sensitive Data in Transit Unencrypted),
         WSTG-CRYP-04 (Weak Encryption).

Fills cryptography testing gaps identified in Phase 46.
"""
import re
import ssl
import socket
import logging
from urllib.parse import urlparse

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Deprecated TLS protocols
WEAK_TLS_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']

# Cipher suites considered weak
WEAK_CIPHER_KEYWORDS = [
    'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'ANON', 'ADH', 'MD5',
    'aNULL', 'eNULL', 'RC2', 'IDEA', 'SEED',
]

# Patterns indicating weak hash usage in HTTP responses or HTML
WEAK_HASH_PATTERNS = [
    r'md5\s*\(',
    r'sha1\s*\(',
    r'crc32\s*\(',
    r'hashlib\.md5',
    r'hashlib\.sha1',
    r'Message-Digest Algorithm 5',
    r'password_hash.*md5',
]

# Regex for potential exposed cryptographic material
CRYPTO_EXPOSURE_PATTERNS = {
    'Hardcoded Secret Key': r'(?:secret[_-]?key|SECRET_KEY)\s*=\s*["\'][^"\']{8,}["\']',
    'Hardcoded Encryption Key': r'(?:encrypt[_-]?key|ENCRYPTION_KEY|AES_KEY)\s*=\s*["\'][^"\']{8,}["\']',
    'Hardcoded IV': r'(?:iv|initialization_vector|IV)\s*=\s*["\'][^"\']{8,}["\']',
}


class WSTGCryptographyTester(BaseTester):
    """WSTG-CRYP: Cryptography — weak TLS, padding oracle, weak ciphers, data in transit."""

    TESTER_NAME = 'WSTG-CRYP'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        parsed = urlparse(page.url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # WSTG-CRYP-01: Weak TLS/SSL protocols
        if parsed.scheme == 'https':
            vulns = self._test_weak_tls(host, port, page.url)
            vulnerabilities.extend(vulns)

        # WSTG-CRYP-03: Sensitive data transmitted over HTTP
        vuln = self._test_unencrypted_transmission(page)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-CRYP-02: Padding oracle indicators in responses
        if depth in ('medium', 'deep'):
            vuln = self._test_padding_oracle_indicators(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # WSTG-CRYP-04: Weak hash/crypto patterns in page source
        vuln = self._test_weak_crypto_in_source(page)
        if vuln:
            vulnerabilities.append(vuln)

        # Exposed crypto material in page source
        if depth in ('medium', 'deep'):
            vulns = self._test_exposed_crypto_material(page)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    # ── WSTG-CRYP-01: Weak TLS/SSL ───────────────────────────────────────────

    def _test_weak_tls(self, host: str, port: int, url: str) -> list:
        """Check for support of deprecated TLS versions (TLSv1, TLSv1.1, SSLv3)."""
        found = []
        if not host:
            return found

        # Check using ssl module for deprecated protocol support
        [
            (ssl.PROTOCOL_TLS_CLIENT, 'TLS', 'TLSv1', ssl.TLSVersion.TLSv1)
            if hasattr(ssl, 'TLSVersion') else None,
        ]

        # Use a simple check: try connecting with minimum version set low
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if hasattr(ssl, 'TLSVersion'):
                try:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            cipher = ssock.cipher()
                            found.append(self._build_vuln(
                                name='TLS 1.0 Supported (Deprecated Protocol)',
                                severity='medium',
                                category='WSTG-CRYP-01: Testing for Weak SSL/TLS Ciphers',
                                description='The server accepts TLS 1.0 connections. TLS 1.0 is '
                                            'deprecated (RFC 8996) and subject to attacks including '
                                            'BEAST and POODLE.',
                                impact='Attackers can downgrade connections to TLS 1.0 and exploit '
                                       'known cryptographic weaknesses.',
                                remediation='Disable TLS 1.0 and TLS 1.1. Configure the server to '
                                            'support only TLS 1.2 and TLS 1.3. '
                                            'For Nginx: ssl_protocols TLSv1.2 TLSv1.3;',
                                cwe='CWE-326',
                                cvss=5.9,
                                affected_url=url,
                                evidence=f'TLS 1.0 handshake succeeded. Cipher: {cipher}',
                            ))
                except (ssl.SSLError, OSError, ConnectionRefusedError):
                    pass  # TLS 1.0 not supported — good

                try:
                    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx2.check_hostname = False
                    ctx2.verify_mode = ssl.CERT_NONE
                    ctx2.minimum_version = ssl.TLSVersion.TLSv1_1
                    ctx2.maximum_version = ssl.TLSVersion.TLSv1_1
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                            cipher = ssock.cipher()
                            if not found:  # only if TLS 1.0 wasn't already flagged
                                found.append(self._build_vuln(
                                    name='TLS 1.1 Supported (Deprecated Protocol)',
                                    severity='medium',
                                    category='WSTG-CRYP-01: Testing for Weak SSL/TLS Ciphers',
                                    description='The server accepts TLS 1.1 connections. TLS 1.1 is '
                                                'deprecated (RFC 8996).',
                                    impact='Downgrade attacks to TLS 1.1 expose the connection to '
                                           'weaknesses in the protocol.',
                                    remediation='Disable TLS 1.1. Support only TLS 1.2 and TLS 1.3.',
                                    cwe='CWE-326',
                                    cvss=4.3,
                                    affected_url=url,
                                    evidence=f'TLS 1.1 handshake succeeded. Cipher: {cipher}',
                                ))
                except (ssl.SSLError, OSError, ConnectionRefusedError):
                    pass  # TLS 1.1 not supported — good

        except Exception as e:
            logger.debug(f'TLS version check error for {host}:{port}: {e}')

        # Check for weak ciphers by inspecting current cipher
        try:
            ctx3 = ssl.create_default_context()
            ctx3.check_hostname = False
            ctx3.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx3.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                        for weak_kw in WEAK_CIPHER_KEYWORDS:
                            if weak_kw in cipher_name.upper():
                                found.append(self._build_vuln(
                                    name=f'Weak TLS Cipher Suite in Use: {cipher_name}',
                                    severity='high',
                                    category='WSTG-CRYP-01: Testing for Weak SSL/TLS Ciphers',
                                    description=f'The negotiated TLS cipher suite "{cipher_name}" '
                                                f'contains a known-weak component ({weak_kw}).',
                                    impact='Weak ciphers can be broken by attackers with sufficient '
                                           'resources, exposing encrypted traffic.',
                                    remediation='Configure SSL/TLS to only allow strong cipher suites. '
                                                'Use AES-GCM or ChaCha20-Poly1305. '
                                                'Disable RC4, DES, 3DES, EXPORT, and NULL ciphers.',
                                    cwe='CWE-327',
                                    cvss=7.4,
                                    affected_url=url,
                                    evidence=f'Negotiated cipher: {cipher_name}',
                                ))
                                break
        except Exception as e:
            logger.debug(f'Cipher check error for {host}:{port}: {e}')

        return found

    # ── WSTG-CRYP-03: Unencrypted Transmission ───────────────────────────────

    def _test_unencrypted_transmission(self, page):
        """Detect sensitive data submitted over unencrypted HTTP."""
        if not page.url.startswith('http://'):
            return None

        # Check for password/credit card fields in forms on an HTTP page
        for form in (getattr(page, 'forms', None) or []):
            inputs = getattr(form, 'inputs', []) or []
            has_sensitive = any(
                getattr(i, 'type', '') == 'password'
                or any(k in (getattr(i, 'name', '') or '').lower()
                       for k in ('password', 'credit_card', 'cvv', 'ssn', 'pin'))
                for i in inputs
            )
            if has_sensitive:
                return self._build_vuln(
                    name='Sensitive Form Data Submitted Over Unencrypted HTTP',
                    severity='high',
                    category='WSTG-CRYP-03: Testing for Sensitive Information Sent via Unencrypted Channels',
                    description='A form containing sensitive fields (password, credit card, etc.) '
                                'is served over HTTP and will transmit credentials/data in plaintext.',
                    impact='Network-adjacent attackers can intercept credentials via passive '
                           'sniffing (MITM, public WiFi, rogue access points).',
                    remediation='Serve all pages over HTTPS. Implement HSTS. '
                                'Redirect all HTTP traffic to HTTPS.',
                    cwe='CWE-319',
                    cvss=7.5,
                    affected_url=page.url,
                    evidence='Sensitive form fields found on HTTP page.',
                )
        return None

    # ── WSTG-CRYP-02: Padding Oracle Indicators ──────────────────────────────

    def _test_padding_oracle_indicators(self, url: str):
        """
        Probe for padding oracle-style error message differences.
        Sends requests with modified encrypted tokens and checks for
        distinct error messages that indicate CBC padding oracle.
        """

        # Look for base64/hex cookie values that might be CBC encrypted
        resp = self._make_request('GET', url)
        if not resp:
            return None

        # Check cookies for base64-encoded values of the right length
        for cookie in resp.cookies:
            value = cookie.value or ''
            # Base64 of CBC block-size multiples (16, 32, 48... bytes)
            try:
                import base64
                decoded = base64.b64decode(value + '==', validate=False)
                if len(decoded) >= 16 and len(decoded) % 16 == 0:
                    # Try modifying the last byte of the penultimate block
                    modified = bytearray(decoded)
                    modified[-17] ^= 0x01  # flip 1 bit in penultimate block
                    modified_b64 = base64.b64encode(bytes(modified)).decode()

                    # Send with modified cookie
                    resp2 = self._make_request('GET', url, cookies={cookie.name: modified_b64})
                    resp3 = self._make_request('GET', url, cookies={cookie.name: modified_b64[:-4] + 'AAAA'})

                    if resp2 and resp3:
                        body2 = (resp2.text or '').lower()
                        (resp3.text or '').lower()

                        padding_errors = ['invalid padding', 'padding error', 'decryption error',
                                          'mac mismatch', 'authentication failed', 'invalid token']

                        has_padding_msg = any(e in body2 for e in padding_errors)
                        abs(len(resp2.text or '') - len(resp3.text or '')) > 20

                        if has_padding_msg or (resp2.status_code != resp3.status_code and
                                               resp2.status_code in (200, 500)):
                            return self._build_vuln(
                                name='Potential CBC Padding Oracle in Cookie: ' + cookie.name,
                                severity='high',
                                category='WSTG-CRYP-02: Testing for Padding Oracle',
                                description=f'The cookie "{cookie.name}" appears to be a '
                                            f'base64-encoded, CBC-encrypted value. The application '
                                            f'returns distinct responses for modified ciphertext, '
                                            f'which is a hallmark of a padding oracle vulnerability.',
                                impact='Padding oracle attacks (like POODLE in CBC mode) allow '
                                       'attackers to decrypt the cookie value and forge arbitrary '
                                       'cookies without knowing the encryption key.',
                                remediation='Use authenticated encryption (AES-GCM, ChaCha20-Poly1305) '
                                            'instead of unauthenticated CBC mode. Always verify HMAC '
                                            'before decrypting. Use framework-provided session tokens.',
                                cwe='CWE-649',
                                cvss=7.4,
                                affected_url=url,
                                evidence=f'Cookie: {cookie.name}. Modified ciphertext returned '
                                         f'HTTP {resp2.status_code} vs {resp3.status_code}.',
                            )
            except Exception:
                continue
        return None

    # ── WSTG-CRYP-04: Weak Crypto in Source ──────────────────────────────────

    def _test_weak_crypto_in_source(self, page):
        """Detect weak cryptographic algorithm usage hints in page source."""
        body = getattr(page, 'body', '') or ''
        for pattern in WEAK_HASH_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return self._build_vuln(
                    name='Weak Cryptographic Hash Algorithm Detected in Page Source',
                    severity='medium',
                    category='WSTG-CRYP-04: Testing for Weak Encryption',
                    description='The page source contains references to weak cryptographic hash '
                                f'functions (MD5, SHA-1). Pattern matched: {pattern}.',
                    impact='MD5 and SHA-1 are cryptographically broken and should not be '
                           'used for security purposes (password hashing, integrity checks).',
                    remediation='Replace MD5/SHA-1 with SHA-256 or stronger (SHA-3, BLAKE2). '
                                'For password hashing, use bcrypt, scrypt, or Argon2.',
                    cwe='CWE-327',
                    cvss=4.3,
                    affected_url=page.url,
                    evidence=f'Weak hash pattern found in source: {pattern}',
                )
        return None

    # ── Exposed Crypto Material ───────────────────────────────────────────────

    def _test_exposed_crypto_material(self, page) -> list:
        """Detect hardcoded encryption keys or IVs in page source."""
        found = []
        body = getattr(page, 'body', '') or ''
        for name, pattern in CRYPTO_EXPOSURE_PATTERNS.items():
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                found.append(self._build_vuln(
                    name=f'Cryptographic Material Exposed in Page Source: {name}',
                    severity='critical',
                    category='WSTG-CRYP-04: Testing for Weak Encryption',
                    description=f'A cryptographic key or IV appears to be hardcoded in the page '
                                f'source: {name}. Exposure of encryption keys completely '
                                f'compromises all data protected by them.',
                    impact='Full compromise of encrypted data. Attackers can decrypt any '
                           'data encrypted with the exposed key.',
                    remediation='Never hardcode cryptographic keys in source code or client-side pages. '
                                'Use environment variables, key management services (HashiCorp Vault, '
                                'AWS KMS), or encrypted configuration stores.',
                    cwe='CWE-321',
                    cvss=9.1,
                    affected_url=page.url,
                    evidence=f'Pattern: {match.group(0)[:100]}',
                ))
        return found
