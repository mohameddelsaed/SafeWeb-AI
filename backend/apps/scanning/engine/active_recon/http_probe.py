"""
Advanced HTTP Probing — Phase 36 enhancements.

New capabilities:
  - Favicon hash calculation (mmh3 for Shodan-style lookup)
  - JARM TLS fingerprint generation
  - Technology fingerprinting from headers
  - CDN origin hunting via header analysis
  - Screenshot-readiness detection
"""
from __future__ import annotations

import logging
import struct
import time
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Favicon hash (Shodan mmh3 style)
# ────────────────────────────────────────────────────────────────────────────

def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Minimal MurmurHash3 32-bit implementation (no external deps)."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(nblocks):
        k1 = struct.unpack_from('<I', data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Return as signed 32-bit int (Shodan convention)
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def compute_favicon_hash(favicon_bytes: bytes) -> int:
    """Compute Shodan-style favicon hash (base64 → mmh3)."""
    import base64
    encoded = base64.encodebytes(favicon_bytes)
    return _mmh3_32(encoded)


KNOWN_FAVICON_HASHES = {
    116323821: 'Jenkins',
    -1293291044: 'Apache Default',
    -247388890: 'Grafana',
    988422585: 'Spring Boot',
    -1713951182: 'Kibana',
    81586820: 'GitLab',
    -1293291044: 'Nginx Default',
    -1022954091: 'WordPress',
    1848946384: 'Jira',
    586765995: 'SonarQube',
}


def identify_favicon(favicon_hash: int) -> str | None:
    """Identify technology from favicon hash."""
    return KNOWN_FAVICON_HASHES.get(favicon_hash)


# ────────────────────────────────────────────────────────────────────────────
# Technology fingerprinting via headers
# ────────────────────────────────────────────────────────────────────────────

HEADER_SIGNATURES = {
    'server': {
        'nginx': 'Nginx',
        'apache': 'Apache',
        'cloudflare': 'Cloudflare',
        'microsoft-iis': 'IIS',
        'litespeed': 'LiteSpeed',
        'openresty': 'OpenResty',
        'caddy': 'Caddy',
        'gunicorn': 'Gunicorn',
        'uvicorn': 'Uvicorn',
        'express': 'Express.js',
        'kestrel': 'Kestrel (.NET)',
    },
    'x-powered-by': {
        'php': 'PHP',
        'asp.net': 'ASP.NET',
        'express': 'Express.js',
        'next.js': 'Next.js',
        'nuxt': 'Nuxt.js',
        'flask': 'Flask',
        'django': 'Django',
    },
    'x-generator': {
        'wordpress': 'WordPress',
        'drupal': 'Drupal',
        'joomla': 'Joomla',
        'hugo': 'Hugo',
        'gatsby': 'Gatsby',
        'jekyll': 'Jekyll',
    },
}

SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'x-xss-protection',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'cross-origin-embedder-policy',
]


def fingerprint_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Fingerprint server technology and security posture from headers.

    Returns {technologies, security_headers, missing_security_headers, raw_server}.
    """
    result: dict[str, Any] = {
        'technologies': [],
        'security_headers': {},
        'missing_security_headers': [],
        'raw_server': '',
        'interesting_headers': {},
    }

    lower_headers = {k.lower(): v for k, v in headers.items()}
    result['raw_server'] = lower_headers.get('server', '')

    # Technology detection
    techs: set[str] = set()
    for header_name, signatures in HEADER_SIGNATURES.items():
        value = lower_headers.get(header_name, '').lower()
        for sig, tech in signatures.items():
            if sig in value:
                techs.add(tech)
    result['technologies'] = sorted(techs)

    # Security headers audit
    for h in SECURITY_HEADERS:
        if h in lower_headers:
            result['security_headers'][h] = lower_headers[h]
        else:
            result['missing_security_headers'].append(h)

    # Interesting headers (leak info)
    interesting_patterns = [
        'x-debug', 'x-runtime', 'x-request-id', 'x-trace',
        'x-amzn', 'x-azure', 'x-goog', 'x-cache',
        'via', 'x-served-by', 'x-backend', 'x-upstream',
    ]
    for key, value in lower_headers.items():
        for pat in interesting_patterns:
            if pat in key:
                result['interesting_headers'][key] = value
                break

    return result


# ────────────────────────────────────────────────────────────────────────────
# CDN / Origin hunting
# ────────────────────────────────────────────────────────────────────────────

CDN_HEADER_SIGNATURES = {
    'cf-ray': 'Cloudflare',
    'x-cdn': 'Generic CDN',
    'x-cache': 'Cache Layer',
    'x-amz-cf-id': 'CloudFront',
    'x-amz-cf-pop': 'CloudFront',
    'x-azure-ref': 'Azure CDN',
    'x-ms-ref': 'Azure Front Door',
    'x-edge-location': 'CDN Edge',
    'x-fastly-request-id': 'Fastly',
    'x-akamai-transformed': 'Akamai',
    'x-vercel-id': 'Vercel',
    'x-netlify-request-id': 'Netlify',
}

ORIGIN_LEAK_HEADERS = [
    'x-backend-server',
    'x-upstream',
    'x-origin-server',
    'x-real-server',
    'x-served-by',
    'x-host',
    'x-forwarded-server',
    'via',
]


def detect_cdn_and_origin(headers: dict[str, str]) -> dict[str, Any]:
    """Detect CDN provider and look for origin server leaks.

    Returns {cdn_detected, cdn_provider, origin_hints, cache_status}.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    result: dict[str, Any] = {
        'cdn_detected': False,
        'cdn_providers': [],
        'origin_hints': [],
        'cache_status': None,
    }

    # CDN detection
    providers: set[str] = set()
    for header, provider in CDN_HEADER_SIGNATURES.items():
        if header in lower_headers:
            providers.add(provider)

    if providers:
        result['cdn_detected'] = True
        result['cdn_providers'] = sorted(providers)

    # Origin hints
    for header in ORIGIN_LEAK_HEADERS:
        value = lower_headers.get(header)
        if value:
            result['origin_hints'].append({
                'header': header,
                'value': value,
            })

    # Cache status
    cache_header = lower_headers.get('x-cache', '')
    if cache_header:
        result['cache_status'] = cache_header

    return result


# ────────────────────────────────────────────────────────────────────────────
# JARM TLS fingerprint (simplified)
# ────────────────────────────────────────────────────────────────────────────

KNOWN_JARM_FINGERPRINTS = {
    '27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d': 'Nginx',
    '29d29d15d29d29d29c29d29d29d29dce8f1fd22d9b0aad44ebeb158f5c1b30': 'Apache',
    '2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c0d7ca6ad8388057924be83dfc6a': 'IIS',
    '29d29d00029d29d00041d41d00041d2aa5ce6a70de7ba95aef77a77b00a0af': 'Cloudflare',
}


def compute_jarm_stub(host: str, port: int = 443) -> dict[str, Any]:
    """Generate a JARM-like TLS fingerprint stub.

    Full JARM requires 10 TLS connections with varying parameters.
    This returns metadata about the approach without making connections.
    """
    return {
        'host': host,
        'port': port,
        'fingerprint': None,
        'note': 'Full JARM requires 10 TLS handshakes; use jarm CLI for production',
        'known_fingerprints_count': len(KNOWN_JARM_FINGERPRINTS),
    }


def lookup_jarm(fingerprint: str) -> str | None:
    """Lookup a JARM fingerprint in the known database."""
    return KNOWN_JARM_FINGERPRINTS.get(fingerprint)


# ────────────────────────────────────────────────────────────────────────────
# Screenshot readiness detection
# ────────────────────────────────────────────────────────────────────────────

def check_screenshot_readiness(headers: dict[str, str],
                                status_code: int = 200) -> dict[str, Any]:
    """Check if a target is suitable for screenshot capture.

    Returns {screenshottable, content_type, reasons, csp_blocks_embed}.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    content_type = lower_headers.get('content-type', '')

    result: dict[str, Any] = {
        'screenshottable': False,
        'content_type': content_type,
        'reasons': [],
        'csp_blocks_embed': False,
        'status_code': status_code,
    }

    # Check content type
    if 'text/html' in content_type:
        result['screenshottable'] = True
    else:
        result['reasons'].append(f'Non-HTML content type: {content_type}')

    # Check status
    if status_code >= 400:
        result['screenshottable'] = False
        result['reasons'].append(f'Error status code: {status_code}')

    # Check X-Frame-Options
    xfo = lower_headers.get('x-frame-options', '').lower()
    if xfo in ('deny', 'sameorigin'):
        result['reasons'].append(f'X-Frame-Options: {xfo}')

    # Check CSP frame-ancestors
    csp = lower_headers.get('content-security-policy', '')
    if "frame-ancestors 'none'" in csp or "frame-ancestors 'self'" in csp:
        result['csp_blocks_embed'] = True
        result['reasons'].append('CSP frame-ancestors blocks embedding')

    return result


# ────────────────────────────────────────────────────────────────────────────
# Aggregator: run full enhanced HTTP probing
# ────────────────────────────────────────────────────────────────────────────

def run_enhanced_http_probe(url: str, headers: dict[str, str] | None = None,
                            status_code: int = 200,
                            favicon_bytes: bytes | None = None,
                            depth: str = 'medium') -> dict[str, Any]:
    """Orchestrate all enhanced HTTP probing methods.

    Returns {fingerprint, cdn, screenshot, favicon, jarm, stats}.
    """
    start = time.time()
    headers = headers or {}

    result: dict[str, Any] = {
        'fingerprint': {},
        'cdn': {},
        'screenshot': {},
        'favicon': {},
        'jarm': {},
        'stats': {'duration': 0.0},
    }

    # Always run header fingerprinting
    result['fingerprint'] = fingerprint_headers(headers)

    # CDN detection
    result['cdn'] = detect_cdn_and_origin(headers)

    if depth in ('medium', 'deep'):
        # Screenshot readiness
        result['screenshot'] = check_screenshot_readiness(headers, status_code)

        # Favicon hash
        if favicon_bytes:
            fhash = compute_favicon_hash(favicon_bytes)
            tech = identify_favicon(fhash)
            result['favicon'] = {
                'hash': fhash,
                'identified_tech': tech,
                'shodan_query': f'http.favicon.hash:{fhash}',
            }

    if depth == 'deep':
        # JARM stub
        parsed = urlparse(url)
        host = parsed.hostname or ''
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        result['jarm'] = compute_jarm_stub(host, port)

    result['stats']['duration'] = round(time.time() - start, 3)
    return result
