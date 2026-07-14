"""
SSLAnalyzer — Checks TLS/SSL configuration for security issues.
Maps to OWASP A02:2021 Cryptographic Failures.
"""
import logging
import ssl
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SSLAnalyzer:
    """Analyze SSL/TLS configuration of a target."""

    def analyze(self, url: str) -> list:
        """Analyze SSL/TLS security of the target."""
        vulnerabilities = []
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # Check if HTTPS is used
        if parsed.scheme != 'https':
            vulnerabilities.append({
                'name': 'HTTPS Not Enforced',
                'severity': 'high',
                'category': 'Cryptographic Failures',
                'description': 'The website is accessible over unencrypted HTTP.',
                'impact': 'All data transmitted between the user and server can be intercepted by attackers on the network.',
                'remediation': 'Enforce HTTPS across the entire site. Redirect all HTTP traffic to HTTPS and enable HSTS.',
                'cwe': 'CWE-319',
                'cvss': 7.5,
                'affected_url': url,
                'evidence': f'Site accessed via {parsed.scheme}://',
            })
            return vulnerabilities

        try:
            # Create SSL context and connect
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()

                    # Check protocol version
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    if protocol_version in weak_protocols:
                        vulnerabilities.append({
                            'name': f'Weak TLS Protocol: {protocol_version}',
                            'severity': 'high',
                            'category': 'Cryptographic Failures',
                            'description': f'The server supports outdated protocol {protocol_version}.',
                            'impact': 'Outdated TLS versions have known vulnerabilities that can be exploited to decrypt traffic.',
                            'remediation': 'Disable TLS 1.0 and 1.1. Only support TLS 1.2 and 1.3.',
                            'cwe': 'CWE-326',
                            'cvss': 7.4,
                            'affected_url': url,
                            'evidence': f'Negotiated protocol: {protocol_version}',
                        })

                    # Check cipher strength
                    if cipher:
                        cipher_name, _, key_length = cipher
                        weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon']
                        for weak in weak_ciphers:
                            if weak.lower() in cipher_name.lower():
                                vulnerabilities.append({
                                    'name': f'Weak Cipher Suite: {cipher_name}',
                                    'severity': 'medium',
                                    'category': 'Cryptographic Failures',
                                    'description': f'The server uses a weak cipher suite: {cipher_name}.',
                                    'impact': 'Weak cipher suites can be broken by attackers, compromising the confidentiality of communications.',
                                    'remediation': 'Configure the server to use strong cipher suites only (e.g., AES-GCM, ChaCha20-Poly1305).',
                                    'cwe': 'CWE-327',
                                    'cvss': 5.9,
                                    'affected_url': url,
                                    'evidence': f'Cipher: {cipher_name}, Key length: {key_length}',
                                })
                                break

            # Check certificate validity with verification
            try:
                verify_context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with verify_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            # Check expiry
                            not_after_str = cert.get('notAfter', '')
                            if not_after_str:
                                not_after = ssl.cert_time_to_seconds(not_after_str)
                                import time
                                if not_after < time.time():
                                    vulnerabilities.append({
                                        'name': 'Expired SSL Certificate',
                                        'severity': 'critical',
                                        'category': 'Cryptographic Failures',
                                        'description': 'The SSL certificate has expired.',
                                        'impact': 'Browsers will display security warnings. Users may be vulnerable to man-in-the-middle attacks.',
                                        'remediation': 'Renew the SSL/TLS certificate immediately.',
                                        'cwe': 'CWE-295',
                                        'cvss': 9.1,
                                        'affected_url': url,
                                        'evidence': f'Certificate expired: {not_after_str}',
                                    })
            except ssl.SSLCertVerificationError as e:
                vulnerabilities.append({
                    'name': 'Invalid SSL Certificate',
                    'severity': 'high',
                    'category': 'Cryptographic Failures',
                    'description': f'SSL certificate validation failed: {str(e)[:200]}',
                    'impact': 'Users may be vulnerable to man-in-the-middle attacks. Browsers will show security warnings.',
                    'remediation': 'Obtain a valid SSL certificate from a trusted Certificate Authority (CA).',
                    'cwe': 'CWE-295',
                    'cvss': 7.4,
                    'affected_url': url,
                    'evidence': str(e)[:500],
                })
            except Exception:
                pass

        except socket.timeout:
            logger.warning(f'SSL check timed out for {hostname}')
        except Exception as e:
            logger.warning(f'SSL analysis error for {hostname}: {e}')

        return vulnerabilities
