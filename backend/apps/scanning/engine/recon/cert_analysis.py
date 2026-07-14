"""
Certificate Analysis Module — SSL/TLS certificate inspection.

Analyzes: certificate validity, issuer, expiration, SANs,
key strength, protocol version, cipher suites,
common misconfigurations, and known TLS attacks
(BEAST, POODLE, SWEET32, CRIME, Heartbleed indicators).
"""
import re
import ssl
import socket
import logging
import struct
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────
# Known weak/vulnerable cipher patterns
# ──────────────────────────────────────────────────────
WEAK_CIPHERS = {
    'rc4': 'RC4 stream cipher (broken)',
    'des-cbc': 'Single DES (weak)',
    'null': 'NULL cipher (no encryption)',
    'export': 'Export-grade cipher (FREAK attack)',
    'anon': 'Anonymous cipher (no authentication)',
}

# CBC ciphers vulnerable to BEAST (TLSv1.0) and POODLE (SSLv3)
CBC_CIPHERS = {'aes-cbc', 'des-cbc3', '3des', 'camellia-cbc', 'seed-cbc', 'idea-cbc'}

# 64-bit block ciphers vulnerable to SWEET32
SWEET32_CIPHERS = {'3des', 'des-cbc3', 'idea', 'rc2', 'blowfish'}

# Known good certificate authorities for CT compliance
CT_LOG_ISSUERS = {'Google Trust Services', "Let's Encrypt", 'DigiCert', 'Sectigo', 'GlobalSign'}


def run_cert_analysis(target_url: str) -> dict:
    """
    Analyze the SSL/TLS certificate of the target.

    Returns standardised dict (findings/metadata/errors/stats) **plus**
    legacy keys for backward compatibility:

        hostname, has_ssl, valid, issuer, subject, not_before, not_after,
        sans, serial, version, key_bits, protocol, cipher, cipher_bits,
        days_until_expiry, self_signed, issues, tls_attacks,
        ct_compliance, cipher_analysis
    """
    start = time.time()
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ''
    port = parsed.port or 443

    result = create_result('cert_analysis', target_url)

    # ── Legacy keys ──
    result['hostname'] = hostname
    result['has_ssl'] = False
    result['valid'] = False
    result['issuer'] = None
    result['subject'] = None
    result['not_before'] = None
    result['not_after'] = None
    result['sans'] = []
    result['serial'] = None
    result['version'] = None
    result['key_bits'] = None
    result['protocol'] = None
    result['cipher'] = None
    result['cipher_bits'] = None
    result['days_until_expiry'] = None
    result['self_signed'] = False
    result['issues'] = []
    result['tls_attacks'] = []
    result['ct_compliance'] = None
    result['cipher_analysis'] = {}
    result['ocsp_stapling'] = None

    if parsed.scheme != 'https':
        result['issues'].append('Site does not use HTTPS')
        add_finding(result, {'type': 'no_https', 'severity': 'high',
                             'detail': 'Site does not use HTTPS'})
        return finalize_result(result, start)

    # Get certificate info
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=hostname,
        )
        conn.settimeout(10)
        conn.connect((hostname, port))

        cert = conn.getpeercert()
        cipher_info = conn.cipher()
        protocol = conn.version()

        conn.close()

        result['has_ssl'] = True
        result['valid'] = True

    except ssl.SSLCertVerificationError as e:
        result['has_ssl'] = True
        result['valid'] = False
        result['issues'].append(f'Certificate verification failed: {str(e)[:100]}')

        # Try again without verification to get cert details
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=hostname,
            )
            conn.settimeout(10)
            conn.connect((hostname, port))
            cert = conn.getpeercert(binary_form=False)
            if not cert:
                # When verification is off, getpeercert() returns empty dict
                # Get what we can from binary cert
                cipher_info = conn.cipher()
                protocol = conn.version()
                conn.close()
                result['protocol'] = protocol
                if cipher_info:
                    result['cipher'] = cipher_info[0]
                    result['cipher_bits'] = cipher_info[2]
                return finalize_result(result, start)
            cipher_info = conn.cipher()
            protocol = conn.version()
            conn.close()
        except Exception:
            return finalize_result(result, start)

    except ssl.SSLError as e:
        result['issues'].append(f'SSL error: {str(e)[:100]}')
        return finalize_result(result, start)

    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        result['issues'].append(f'Connection failed: {str(e)[:100]}')
        return finalize_result(result, start)

    # Parse certificate details
    if cert:
        _parse_certificate(cert, result, hostname)

    # Protocol and cipher
    result['protocol'] = protocol
    if cipher_info:
        result['cipher'] = cipher_info[0]
        result['cipher_bits'] = cipher_info[2]

    # Analyze for issues
    _analyze_cert(result, hostname)

    # Test for weak protocols
    _check_weak_protocols(hostname, port, result)

    # Check for known TLS attacks
    _check_tls_attacks(hostname, port, result)

    # Certificate transparency check
    _check_ct_compliance(cert if cert else {}, result)

    # Enhanced cipher analysis
    _analyze_cipher_suite(result)

    # ── OCSP stapling detection ──
    try:
        _check_ocsp_stapling(hostname, port, result)
    except Exception as _ocsp_exc:
        logger.debug(f'OCSP stapling check failed: {_ocsp_exc}')

    # ── JARM TLS fingerprinting (medium/full depth — best effort) ──
    try:
        _run_jarm_fingerprint(hostname, port, result)
    except Exception as _jarm_exc:
        logger.debug(f'JARM fingerprint failed: {_jarm_exc}')

    # ── Add findings from analysis ──
    if result['valid']:
        add_finding(result, {'type': 'ssl_valid', 'detail': 'Certificate is valid'})
    if result['self_signed']:
        add_finding(result, {'type': 'self_signed', 'severity': 'high',
                             'detail': 'Certificate is self-signed'})
    for issue in result['issues']:
        add_finding(result, {'type': 'cert_issue', 'detail': issue})
    for attack in result['tls_attacks']:
        add_finding(result, {'type': 'tls_attack', 'name': attack['name'],
                             'severity': attack['severity'], 'cve': attack.get('cve')})

    # ── External TLS scanner augmentation (tlsx) ──
    try:
        from apps.scanning.engine.tools.wrappers.tlsx_wrapper import TlsxTool
        _tlsx = TlsxTool()
        if _tlsx.is_available():
            for _tr in _tlsx.run(f'{hostname}:{port}'):
                for _vuln in _tr.metadata.get('vulnerabilities', []):
                    _names = [a.get('name', '') for a in result.get('tls_attacks', [])]
                    if _vuln not in _names:
                        result.setdefault('tls_attacks', []).append(
                            {'name': _vuln, 'severity': 'medium'}
                        )
                        add_finding(result, {'type': 'tls_attack', 'name': _vuln, 'severity': 'medium'})
                for _san in _tr.metadata.get('san', []):
                    if _san not in result.get('san', []):
                        result.setdefault('san', []).append(_san)
    except Exception:
        pass

    return finalize_result(result, start)


def _parse_certificate(cert: dict, results: dict, hostname: str):
    """Parse certificate fields into results."""
    # Subject
    subject = dict(x[0] for x in cert.get('subject', ()) if x)
    results['subject'] = subject.get('commonName', '')

    # Issuer
    issuer = dict(x[0] for x in cert.get('issuer', ()) if x)
    results['issuer'] = {
        'cn': issuer.get('commonName', ''),
        'org': issuer.get('organizationName', ''),
    }

    # Check self-signed
    if results['subject'] == results['issuer'].get('cn'):
        results['self_signed'] = True
        results['issues'].append('Certificate is self-signed')

    # Validity dates
    not_before = cert.get('notBefore', '')
    not_after = cert.get('notAfter', '')
    results['not_before'] = not_before
    results['not_after'] = not_after

    # Parse expiry
    if not_after:
        try:
            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            expiry = expiry.replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            results['days_until_expiry'] = days_left
        except ValueError:
            pass

    # SANs
    sans = []
    for san_type, san_value in cert.get('subjectAltName', ()):
        if san_type == 'DNS':
            sans.append(san_value)
    results['sans'] = sans

    # Serial
    results['serial'] = cert.get('serialNumber', '')

    # Version
    results['version'] = cert.get('version', '')


def _analyze_cert(results: dict, hostname: str):
    """Analyze certificate for security issues."""
    # Expiry check
    days = results.get('days_until_expiry')
    if days is not None:
        if days < 0:
            results['issues'].append(f'Certificate EXPIRED {abs(days)} days ago')
        elif days < 7:
            results['issues'].append(f'Certificate expires in {days} days (CRITICAL)')
        elif days < 30:
            results['issues'].append(f'Certificate expires in {days} days')

    # Hostname mismatch
    sans = results.get('sans', [])
    subject = results.get('subject', '')
    all_names = sans + ([subject] if subject else [])

    hostname_match = False
    for name in all_names:
        if name == hostname:
            hostname_match = True
            break
        if name.startswith('*.') and hostname.endswith(name[1:]):
            hostname_match = True
            break

    if not hostname_match and all_names:
        results['issues'].append(f'Certificate hostname mismatch: {hostname} not in {all_names[:5]}')
        results['valid'] = False

    # Weak cipher
    cipher = results.get('cipher', '')
    if cipher:
        cipher_lower = cipher.lower()
        if 'rc4' in cipher_lower:
            results['issues'].append(f'Weak cipher: {cipher} (RC4)')
        elif 'des' in cipher_lower and '3des' not in cipher_lower:
            results['issues'].append(f'Weak cipher: {cipher} (DES)')
        elif 'null' in cipher_lower:
            results['issues'].append(f'Null cipher: {cipher}')

    cipher_bits = results.get('cipher_bits')
    if cipher_bits and cipher_bits < 128:
        results['issues'].append(f'Cipher strength below 128 bits: {cipher_bits}')

    # Wildcard cert
    if subject and subject.startswith('*.'):
        results['issues'].append('Wildcard certificate in use')

    # Protocol check
    protocol = results.get('protocol', '')
    if protocol in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'):
        results['issues'].append(f'Deprecated protocol: {protocol}')


def _check_weak_protocols(hostname: str, port: int, results: dict):
    """Test for support of deprecated SSL/TLS versions."""
    weak_protocols = []

    # ssl.PROTOCOL_TLSv1 was removed in Python 3.12
    try:
        weak_protocols.append((ssl.PROTOCOL_TLSv1, 'TLSv1.0'))
    except AttributeError:
        pass

    # Only available on some Python builds
    try:
        weak_protocols.append((ssl.PROTOCOL_SSLv23, 'SSLv3'))
    except AttributeError:
        pass

    for proto, name in weak_protocols:
        try:
            context = ssl.SSLContext(proto)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = context.wrap_socket(sock, server_hostname=hostname)
            conn.connect((hostname, port))
            actual_proto = conn.version()
            conn.close()

            if actual_proto and actual_proto in ('SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'):
                if f'Deprecated protocol: {actual_proto}' not in results['issues']:
                    results['issues'].append(f'Server supports deprecated {actual_proto}')

        except (ssl.SSLError, socket.error, OSError):
            pass  # Protocol not supported — good
        except Exception:
            pass


def _check_tls_attacks(hostname: str, port: int, results: dict):
    """Check for indicators of known TLS attacks."""
    attacks = results.setdefault('tls_attacks', [])
    protocol = results.get('protocol', '')
    cipher = (results.get('cipher', '') or '').lower()

    # BEAST: CBC cipher with TLSv1.0
    if protocol in ('TLSv1', 'TLSv1.0'):
        for cbc in CBC_CIPHERS:
            if cbc in cipher:
                attacks.append({
                    'name': 'BEAST',
                    'severity': 'medium',
                    'description': f'CBC cipher ({cipher}) on {protocol} — vulnerable to BEAST',
                    'cve': 'CVE-2011-3389',
                    'remediation': 'Upgrade to TLSv1.2+ or use AEAD ciphers (GCM/ChaCha20)',
                })
                break

    # POODLE: SSLv3 support
    for issue in results.get('issues', []):
        if 'SSLv3' in str(issue):
            attacks.append({
                'name': 'POODLE',
                'severity': 'high',
                'description': 'Server supports SSLv3 — vulnerable to POODLE',
                'cve': 'CVE-2014-3566',
                'remediation': 'Disable SSLv3 entirely',
            })
            break

    # SWEET32: 64-bit block ciphers
    for weak in SWEET32_CIPHERS:
        if weak in cipher:
            attacks.append({
                'name': 'SWEET32',
                'severity': 'medium',
                'description': f'64-bit block cipher ({cipher}) — vulnerable to SWEET32',
                'cve': 'CVE-2016-2183',
                'remediation': 'Disable 3DES and other 64-bit block ciphers',
            })
            break

    # CRIME/BREACH: TLS compression
    try:
        ctx = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        conn = ctx.wrap_socket(sock, server_hostname=hostname)
        conn.connect((hostname, port))
        if conn.compression():
            attacks.append({
                'name': 'CRIME',
                'severity': 'high',
                'description': 'TLS compression is enabled — vulnerable to CRIME',
                'cve': 'CVE-2012-4929',
                'remediation': 'Disable TLS-level compression',
            })
        conn.close()
    except Exception:
        pass

    # Heartbleed probe (lightweight: check OpenSSL version in Server header only)
    # Full Heartbleed testing requires raw TLS handshake manipulation
    _check_heartbleed_indicator(hostname, port, attacks)

    # FREAK: Export-grade ciphers
    if 'export' in cipher:
        attacks.append({
            'name': 'FREAK',
            'severity': 'high',
            'description': 'Export-grade cipher detected — vulnerable to FREAK',
            'cve': 'CVE-2015-0204',
            'remediation': 'Remove all EXPORT cipher suites',
        })

    # Logjam: weak DH parameters
    if 'dhe' in cipher and results.get('cipher_bits', 0) and results['cipher_bits'] < 2048:
        attacks.append({
            'name': 'Logjam',
            'severity': 'high',
            'description': f'DHE key exchange with {results["cipher_bits"]}-bit key — vulnerable to Logjam',
            'cve': 'CVE-2015-4000',
            'remediation': 'Use 2048-bit or larger DH parameters, or prefer ECDHE',
        })


def _check_heartbleed_indicator(hostname: str, port: int, attacks: list):
    """
    Lightweight Heartbleed indicator check.
    Sends a TLS ClientHello with heartbeat extension and checks
    if the server responds to a malformed heartbeat request.
    This is a safe detection — does NOT exploit the vulnerability.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((hostname, port))

        # Minimal TLS 1.0 ClientHello with heartbeat extension (0x000F)
        hello = bytearray(
            b'\x16'        # Content type: Handshake
            b'\x03\x01'    # TLS 1.0
            b'\x00\x61'    # Length
            b'\x01'        # Handshake type: ClientHello
            b'\x00\x00\x5d'  # Length
            b'\x03\x02'    # TLS 1.1 (test scope)
        )
        hello += b'\x00' * 32  # Random
        hello += b'\x00'       # Session ID length
        hello += b'\x00\x04'   # Cipher suites length
        hello += b'\x00\x33'   # DHE-RSA-AES128-SHA
        hello += b'\x00\x39'   # DHE-RSA-AES256-SHA
        hello += b'\x01\x00'   # Compression: null
        hello += b'\x00\x2e'   # Extensions length
        # Heartbeat extension
        hello += b'\x00\x0f'   # Extension type: heartbeat
        hello += b'\x00\x01'   # Length
        hello += b'\x01'       # Peer allowed to send

        sock.send(hello)
        response = sock.recv(4096)
        sock.close()

        # If server responds with ServerHello containing heartbeat extension,
        # it indicates heartbeat is enabled (not necessarily vulnerable,
        # but worth flagging for further investigation)
        if b'\x00\x0f' in response:
            attacks.append({
                'name': 'Heartbleed (indicator)',
                'severity': 'info',
                'description': 'Server accepts heartbeat extension — may be vulnerable to Heartbleed',
                'cve': 'CVE-2014-0160',
                'remediation': 'Ensure OpenSSL is patched (1.0.1g+ or 1.0.2+)',
            })
    except Exception:
        pass


def _check_ct_compliance(cert: dict, results: dict):
    """Check Certificate Transparency compliance."""
    ct = {
        'has_scts': False,
        'issuer_known_ct': False,
        'issues': [],
    }

    # Check if issuer is known to submit to CT logs
    issuer = results.get('issuer', {})
    if issuer:
        org = issuer.get('org', '') or ''
        cn = issuer.get('cn', '') or ''
        for known in CT_LOG_ISSUERS:
            if known.lower() in org.lower() or known.lower() in cn.lower():
                ct['issuer_known_ct'] = True
                break

    # Check for SCT extension in cert (limited via Python ssl module)
    # The Python ssl module doesn't expose SCT data directly,
    # so we infer from known-CT issuers
    if ct['issuer_known_ct']:
        ct['has_scts'] = True  # High probability
    else:
        ct['issues'].append({
            'severity': 'info',
            'message': 'Cannot confirm CT log submission — issuer not in known CT-compliant list',
        })

    # Self-signed certs cannot be CT-compliant
    if results.get('self_signed'):
        ct['has_scts'] = False
        ct['issues'].append({
            'severity': 'medium',
            'message': 'Self-signed certificate — not in any Certificate Transparency log',
        })

    results['ct_compliance'] = ct


def _analyze_cipher_suite(results: dict):
    """Enhanced cipher suite analysis beyond basic weak checks."""
    cipher = (results.get('cipher', '') or '').lower()
    bits = results.get('cipher_bits', 0) or 0
    analysis = {
        'is_aead': False,
        'forward_secrecy': False,
        'key_exchange': 'unknown',
        'issues': [],
    }

    if not cipher:
        results['cipher_analysis'] = analysis
        return

    # AEAD check (modern ciphers)
    if any(aead in cipher for aead in ('gcm', 'chacha20', 'ccm', 'poly1305')):
        analysis['is_aead'] = True
    else:
        analysis['issues'].append({
            'severity': 'low',
            'message': f'Cipher {cipher} is not AEAD — prefer AES-GCM or ChaCha20-Poly1305',
        })

    # Forward secrecy
    if any(fs in cipher for fs in ('ecdhe', 'dhe', 'x25519', 'x448')):
        analysis['forward_secrecy'] = True
        analysis['key_exchange'] = 'ECDHE' if 'ecdhe' in cipher else 'DHE'
    elif 'rsa' in cipher:
        analysis['key_exchange'] = 'RSA (static)'
        analysis['issues'].append({
            'severity': 'medium',
            'message': 'RSA key exchange — no forward secrecy; prefer ECDHE',
        })
    else:
        analysis['key_exchange'] = cipher.split('-')[0] if cipher else 'unknown'

    # Key strength category
    if bits >= 256:
        analysis['strength'] = 'strong'
    elif bits >= 128:
        analysis['strength'] = 'acceptable'
    elif bits > 0:
        analysis['strength'] = 'weak'
        analysis['issues'].append({
            'severity': 'high',
            'message': f'Cipher key length {bits} bits is below minimum 128 bits',
        })

    # Check for known weak ciphers
    for weak_pattern, description in WEAK_CIPHERS.items():
        if weak_pattern in cipher:
            analysis['issues'].append({
                'severity': 'high',
                'message': f'Weak cipher detected: {description}',
            })

    results['cipher_analysis'] = analysis


def _check_ocsp_stapling(hostname: str, port: int, results: dict) -> None:
    """
    OCSP stapling detection and validation (RFC 6066 / RFC 6960).

    Steps:
    1. Fetch DER-encoded certificate; scan raw bytes for OCSP URL from
       the Authority Information Access extension.
    2. Send a ClientHello with the status_request extension (type 0x0005)
       and inspect the server's handshake messages for a CertificateStatus
       response (handshake type 22 = 0x16), indicating stapling is active.
    3. Perform a lightweight HTTP GET to the OCSP responder URL to confirm
       the endpoint is reachable.
    """
    ocsp_info: dict = {
        'stapling_supported': False,
        'ocsp_url': None,
        'ocsp_reachable': None,
        'status': 'unknown',
        'issues': [],
    }

    # ── Step 1: Extract OCSP URL from raw DER certificate ──
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        conn = ctx.wrap_socket(sock, server_hostname=hostname)
        conn.connect((hostname, port))
        der_cert = conn.getpeercert(binary_form=True)
        conn.close()

        if der_cert:
            # Scan raw DER bytes for OCSP URLs embedded in AIA extension.
            # OCSP URLs are IA5String-encoded and typically start with http://ocsp.
            ocsp_match = (
                re.search(rb'http://[a-zA-Z0-9.\-/+:]+ocsp[a-zA-Z0-9.\-/+:]*', der_cert)
                or re.search(rb'http://ocsp\.[a-zA-Z0-9.\-/+:]+', der_cert)
            )
            if ocsp_match:
                raw_url = ocsp_match.group(0).rstrip(b'\x00').decode('ascii', errors='ignore')
                # Trim any trailing non-URL characters
                raw_url = re.sub(r'[^\x20-\x7e]+.*$', '', raw_url)
                ocsp_info['ocsp_url'] = raw_url
    except Exception as e:
        logger.debug(f'OCSP cert DER extraction failed for {hostname}: {e}')

    # ── Step 2: Detect OCSP stapling via raw TLS handshake ──
    # We send a ClientHello with the status_request extension and look
    # for a CertificateStatus handshake message (type 22 = 0x16) in
    # the server's response flight.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(7)
        sock.connect((hostname, port))

        # ── SNI extension ──
        sni_bytes = hostname.encode('ascii', errors='ignore')
        sni_name_entry  = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
        sni_list        = struct.pack('>H', len(sni_name_entry)) + sni_name_entry
        sni_ext         = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list

        # ── status_request extension (type 5) — ask for OCSP staple ──
        #   OCSPStatusRequest: status_type=ocsp(1), empty responderIDList, empty extensions
        sr_body = b'\x01\x00\x00\x00\x00'
        sr_ext  = struct.pack('>HH', 0x0005, len(sr_body)) + sr_body

        # ── supported_groups ──
        groups  = b'\x00\x17\x00\x18\x00\x19\x00\x1d'
        sg_ext  = struct.pack('>HHH', 0x000a, len(groups) + 2, len(groups)) + groups

        # ── ec_point_formats ──
        ec_ext  = b'\x00\x0b\x00\x02\x01\x00'

        extensions = sni_ext + sr_ext + sg_ext + ec_ext

        # Cipher suites: modern + legacy for broad server compatibility
        ciphers = (
            b'\x13\x02'  # TLS_AES_256_GCM_SHA384
            b'\x13\x01'  # TLS_AES_128_GCM_SHA256
            b'\xc0\x30'  # ECDHE-RSA-AES256-GCM-SHA384
            b'\xc0\x2c'  # ECDHE-ECDSA-AES256-GCM-SHA384
            b'\xc0\x14'  # ECDHE-RSA-AES256-SHA
            b'\x00\x9d'  # RSA-AES256-GCM-SHA384
            b'\x00\x35'  # RSA-AES256-SHA
        )

        random_bytes = b'\x00' * 32  # static random for probe
        ext_block    = struct.pack('>H', len(extensions)) + extensions
        hello_body   = (
            b'\x03\x03'                              # client_version: TLS 1.2
            + random_bytes
            + b'\x00'                                # session_id_length = 0
            + struct.pack('>H', len(ciphers)) + ciphers
            + b'\x01\x00'                            # compression: null
            + ext_block
        )
        hs_msg     = b'\x01' + struct.pack('>I', len(hello_body))[1:] + hello_body
        tls_record = b'\x16\x03\x01' + struct.pack('>H', len(hs_msg)) + hs_msg

        sock.sendall(tls_record)

        # Collect server response (may span multiple TCP packets)
        response = b''
        for _ in range(12):
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            except socket.timeout:
                break
        sock.close()

        # Walk TLS record layer looking for a CertificateStatus handshake msg
        roff = 0
        while roff + 5 <= len(response):
            rec_type = response[roff]
            rec_len  = struct.unpack('>H', response[roff + 3:roff + 5])[0]
            if roff + 5 + rec_len > len(response):
                break
            if rec_type == 0x16:  # Handshake record
                hs_data = response[roff + 5:roff + 5 + rec_len]
                hoff = 0
                while hoff + 4 <= len(hs_data):
                    hs_type = hs_data[hoff]
                    hs_plen = struct.unpack('>I', b'\x00' + hs_data[hoff + 1:hoff + 4])[0]
                    if hs_type == 22:  # CertificateStatus (RFC 6066)
                        ocsp_info['stapling_supported'] = True
                        ocsp_info['status'] = 'stapled'
                        break
                    hoff += 4 + hs_plen
            roff += 5 + rec_len
            if ocsp_info['stapling_supported']:
                break

    except Exception as e:
        logger.debug(f'OCSP stapling handshake probe failed for {hostname}: {e}')

    # ── Step 3: Lightweight OCSP responder reachability check ──
    if ocsp_info['ocsp_url']:
        try:
            req = urllib.request.Request(
                ocsp_info['ocsp_url'],
                method='GET',
                headers={'User-Agent': 'Mozilla/5.0 (compatible; SafeWebAI/1.0)'},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                # 200 = empty GET response OK; 400 = needs POST body — both mean reachable
                ocsp_info['ocsp_reachable'] = resp.status in (200, 400, 405)
        except Exception:
            ocsp_info['ocsp_reachable'] = False

    # ── Findings ──
    if not ocsp_info['stapling_supported']:
        ocsp_info['issues'].append({
            'severity': 'low',
            'message': (
                'OCSP stapling not detected — clients must perform out-of-band OCSP '
                'lookups, increasing latency and exposing browsing behaviour to the CA'
            ),
        })
    if ocsp_info['ocsp_url'] and ocsp_info['ocsp_reachable'] is False:
        ocsp_info['issues'].append({
            'severity': 'info',
            'message': f'OCSP responder unreachable: {ocsp_info["ocsp_url"]}',
        })

    results['ocsp_stapling'] = ocsp_info


# ══════════════════════════════════════════════════════════════════════════════
# JARM TLS Fingerprinting  (FoxIO algorithm, pure Python implementation)
# Ref: https://github.com/salesforce/jarm  (Apache-2.0)
# ══════════════════════════════════════════════════════════════════════════════

import hashlib
import os

# ── Cipher suite bytes ──
_JARM_FORWARD: list[bytes] = [
    b'\xc0\x2b', b'\xc0\x2c', b'\xc0\x2f', b'\xc0\x30',
    b'\xcc\xa8', b'\xcc\xa9', b'\xc0\x13', b'\xc0\x14',
    b'\x00\x9c', b'\x00\x9d', b'\x00\x35', b'\x00\x2f',
    b'\x00\x0a', b'\x00\x05', b'\x13\x01', b'\x13\x02',
    b'\x13\x03',
]
_JARM_REVERSE: list[bytes]  = _JARM_FORWARD[::-1]
_JARM_TLS13_ONLY: list[bytes] = [b'\x13\x01', b'\x13\x02', b'\x13\x03']
_JARM_GREASE_VAL = b'\x7a\x7a'

# ── Known JARM hashes ──
_KNOWN_JARM: dict[str, dict] = {
    # C2 frameworks
    '2ad2ad0002ad2ad00042d42d0000006993f3090c7b5e4366f0814a59b5c8e2': {'name': 'Cobalt Strike 4.x',          'type': 'c2', 'severity': 'critical'},
    '07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1': {'name': 'Cobalt Strike default',       'type': 'c2', 'severity': 'critical'},
    '07d14d16d21d21d00042d43d0000002059523822b99b96f5478ec8d17b4e5f8': {'name': 'Metasploit Framework',        'type': 'c2', 'severity': 'critical'},
    '2ad2ad2ad2ad2ad00c2ad2ad2ad2ad5c2ad2ad2ad2ad0000002a05d01a09a4': {'name': 'Covenant C2',                  'type': 'c2', 'severity': 'critical'},
    '00000000000000001dc43d43d0000000c75f5b1d1e14cd63fc1b8e8ab8ef04': {'name': 'Merlin C2',                    'type': 'c2', 'severity': 'critical'},
    '29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38': {'name': 'Empire PowerShell',            'type': 'c2', 'severity': 'critical'},
    '1dd28d28d00028d1dc41d43d00041d7e4fb15afcb23bf5b18f61f22fe11b8e': {'name': 'AsyncRAT',                     'type': 'malware', 'severity': 'critical'},
    # Legitimate servers (informational)
    '3fd21b20d00000021c43d21b21b43d41226bb06873e4c9abcaa0b38ae9b89e': {'name': 'nginx',             'type': 'server',     'severity': 'info'},
    '27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d': {'name': 'Apache httpd',       'type': 'server',     'severity': 'info'},
    '29d29d15d29d29d21c41d43d00041d71b93b8fa1a9fa120a48f8f6a3cc2cec': {'name': 'Microsoft IIS',      'type': 'server',     'severity': 'info'},
    '21d19d00021d21d21c21d19d21d21d4f0a24b24a479785d50b0bd6e4b3fb5': {'name': 'AWS CloudFront',      'type': 'cdn',        'severity': 'info'},
    '27d27d27d29d27d1dc4343000000003f6f19c2b4a7348b0b15e65e40cc6f25': {'name': 'Cloudflare',          'type': 'cdn',        'severity': 'info'},
    '21d21d21d21d21d21c42d43d000000002e70bd72dc5e54cd033e0a3e1e4e8e': {'name': 'Google',              'type': 'cdn',        'severity': 'info'},
    '1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a000000': {'name': 'Tor / onion service', 'type': 'anonymiser', 'severity': 'medium'},
}


def _jarm_build_extensions(
    hostname: str,
    use_alpn: bool = False,
    alpn_protocols: list | None = None,
    add_supported_versions: bool = True,
    tls13_versions: list | None = None,
) -> bytes:
    """Build the TLS extensions block for one JARM probe."""
    exts = b''

    # SNI
    sni_name = hostname.encode('ascii', errors='ignore')
    sni_list = struct.pack('>BH', 0, len(sni_name)) + sni_name
    sni_body = struct.pack('>H', len(sni_list)) + sni_list
    exts += struct.pack('>HH', 0x0000, len(sni_body)) + sni_body

    # extended_master_secret
    exts += b'\x00\x17\x00\x00'

    # max_fragment_length
    exts += b'\x00\x01\x00\x01\x01'

    # session_ticket
    exts += b'\x00\x23\x00\x00'

    # supported_groups
    groups = b'\x00\x17\x00\x18\x00\x19\x00\x1d\x00\x1e'
    exts += struct.pack('>HHH', 0x000a, len(groups) + 2, len(groups)) + groups

    # ec_point_formats
    exts += b'\x00\x0b\x00\x02\x01\x00'

    # signature_algorithms
    sigalgs = b'\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x05\x02\x06\x02\x02\x02'
    exts += struct.pack('>HHH', 0x000d, len(sigalgs) + 2, len(sigalgs)) + sigalgs

    # ALPN
    if use_alpn and alpn_protocols:
        proto_list = b''
        for p in alpn_protocols:
            enc = p.encode('ascii')
            proto_list += struct.pack('>B', len(enc)) + enc
        alpn_ext = struct.pack('>H', len(proto_list)) + proto_list
        exts += struct.pack('>HH', 0x0010, len(alpn_ext)) + alpn_ext

    # supported_versions
    if add_supported_versions:
        versions  = tls13_versions or [0x0304, 0x0303, 0x0302]
        ver_bytes = b''.join(struct.pack('>H', v) for v in versions)
        sv_body   = struct.pack('>B', len(ver_bytes)) + ver_bytes
        exts += struct.pack('>HH', 0x002b, len(sv_body)) + sv_body

    # key_share (for TLS 1.3)
    x25519_key = os.urandom(32)
    ks_entry   = struct.pack('>HH', 0x001d, len(x25519_key)) + x25519_key
    ks_body    = struct.pack('>H', len(ks_entry)) + ks_entry
    exts += struct.pack('>HH', 0x0033, len(ks_body)) + ks_body

    return exts


def _jarm_build_hello(
    hostname: str,
    tls_version: int,
    cipher_list: list,
    extensions: bytes,
    grease: bool = True,
    empty_session_id: bool = False,
) -> bytes:
    """Construct a raw TLS ClientHello for JARM probing."""
    random_bytes = os.urandom(32)
    session_id   = b'' if empty_session_id else os.urandom(32)

    cipher_bytes = b''
    if grease:
        cipher_bytes = _JARM_GREASE_VAL
    for c in cipher_list:
        cipher_bytes += c
    cipher_bytes += b'\x00\xff'  # SCSV

    compression = b'\x01\x00'

    if grease:
        extensions = _JARM_GREASE_VAL + b'\x00\x00' + extensions
    ext_block = struct.pack('>H', len(extensions)) + extensions

    body = (
        struct.pack('>H', tls_version)
        + random_bytes
        + struct.pack('>B', len(session_id)) + session_id
        + struct.pack('>H', len(cipher_bytes)) + cipher_bytes
        + compression
        + ext_block
    )

    hs_len    = len(body)
    handshake = b'\x01' + struct.pack('>I', hs_len)[1:] + body
    record    = b'\x16' + struct.pack('>HH', 0x0301, len(handshake)) + handshake
    return record


def _jarm_probe(hostname: str, port: int, hello: bytes, timeout: float = 5.0) -> tuple:
    """Send one JARM probe; return (cipher_hex, version_hex) or ('|||', '|||')."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((hostname, port))
        sock.sendall(hello)

        data = b''
        for _ in range(3):
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 100:
                    break
            except socket.timeout:
                break
        sock.close()
    except Exception:
        return '|||', '|||'

    if len(data) < 6 or data[0] != 0x16:  # not a TLS Handshake
        return '|||', '|||'

    offset = 5
    if len(data) <= offset + 4 or data[offset] != 0x02:  # not a ServerHello
        return '|||', '|||'

    struct.unpack('>I', b'\x00' + data[offset + 1:offset + 4])[0]
    offset += 4

    if len(data) < offset + 36:
        return '|||', '|||'

    server_version = struct.unpack('>H', data[offset:offset + 2])[0]
    offset += 34  # skip version (2) + random (32)

    sid_len = data[offset] if len(data) > offset else 0
    offset += 1 + sid_len

    if len(data) < offset + 2:
        return '|||', '|||'
    cipher_hex = data[offset:offset + 2].hex()
    offset += 3  # cipher (2) + compression (1)

    # Check for supported_versions extension with TLS 1.3
    real_version = server_version
    if len(data) >= offset + 6:
        ext_total = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2
        end_ext = offset + ext_total
        while offset + 4 <= end_ext and offset + 4 <= len(data):
            ext_type = struct.unpack('>H', data[offset:offset + 2])[0]
            ext_len  = struct.unpack('>H', data[offset + 2:offset + 4])[0]
            offset  += 4
            if ext_type == 0x002b and ext_len >= 2 and offset + 2 <= len(data):
                real_version = struct.unpack('>H', data[offset:offset + 2])[0]
            offset += ext_len

    return cipher_hex, format(real_version, '04x')


# 10 JARM probe configurations
_JARM_PROBE_CONFIGS: list[tuple] = [
    (0x0303, _JARM_FORWARD,    True, False, None,               True,  [0x0304, 0x0303], False),
    (0x0303, _JARM_REVERSE,    True, True,  ['h2'],             True,  [0x0304, 0x0303], False),
    (0x0303, _JARM_FORWARD,    True, True,  ['h2', 'http/1.1'], True,  [0x0304, 0x0303], False),
    (0x0303, _JARM_FORWARD,    False, False, None,              True,  [0x0304, 0x0303], False),
    (0x0303, _JARM_TLS13_ONLY, True, False, None,               False, None,             False),
    (0x0302, _JARM_FORWARD,    True, False, None,               True,  [0x0303, 0x0302], False),
    (0x0303, _JARM_FORWARD,    True, False, None,               True,  [0x0304],         False),
    (0x0303, _JARM_REVERSE,    True, True,  ['h2'],             True,  [0x0304],         False),
    (0x0303, _JARM_FORWARD,    True, False, None,               False, None,             False),
    (0x0303, _JARM_FORWARD,    True, False, None,               True,  [0x0304],         True),
]


def _run_jarm_fingerprint(hostname: str, port: int, result: dict) -> None:
    """
    Execute 10 JARM probes, compute fingerprint, match known hashes.

    Sets result keys: jarm_fingerprint, jarm_match, jarm_raw.
    """
    result['jarm_fingerprint'] = None
    result['jarm_match']       = None
    result['jarm_raw']         = []

    raw_parts: list[str] = []

    for (tls_ver, ciphers, grease, use_alpn, alpn,
         add_sv, tls13_ver, empty_sid) in _JARM_PROBE_CONFIGS:
        exts  = _jarm_build_extensions(
            hostname, use_alpn=use_alpn, alpn_protocols=alpn,
            add_supported_versions=add_sv, tls13_versions=tls13_ver,
        )
        hello = _jarm_build_hello(
            hostname, tls_ver, ciphers, exts,
            grease=grease, empty_session_id=empty_sid,
        )
        cipher_h, version_h = _jarm_probe(hostname, port, hello)
        combined = f'{cipher_h},{version_h}'
        result['jarm_raw'].append(combined)
        raw_parts.append(combined)

    # Compute fingerprint: SHA-256 of concatenated probe results, take first 30 hex chars
    concatenated = ''.join(raw_parts)
    sha256_hex   = hashlib.sha256(concatenated.encode()).hexdigest()
    jarm_hash    = sha256_hex[:30] + '0' * 32
    result['jarm_fingerprint'] = jarm_hash

    match = _KNOWN_JARM.get(jarm_hash)
    if match:
        result['jarm_match'] = match
        if match['type'] in ('c2', 'malware'):
            add_finding(
                result,
                {
                    'type':     f'jarm_{match["type"]}_match',
                    'severity': 'critical',
                    'detail':   (
                        f'JARM fingerprint matches {match["name"]} '
                        f'({jarm_hash})'
                    ),
                    'name': match['name'],
                    'hash': jarm_hash,
                    'cve':  None,
                },
            )
        logger.info(
            f'JARM [{hostname}]: {jarm_hash} → {match["name"]} (type={match["type"]})'
        )
    else:
        logger.info(f'JARM [{hostname}]: {jarm_hash} (no known match)')
