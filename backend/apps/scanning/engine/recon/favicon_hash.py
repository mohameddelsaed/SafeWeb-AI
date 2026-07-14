"""
Favicon Hash Fingerprinting — FavFreak / Shodan favicon hash identification.

Technique popularized by @m4ll0k / FavFreak:
  1. Download /favicon.ico (and HTML-linked favicons).
  2. Compute MurmurHash3 (32-bit, signed) on the base64-encoded content.
  3. Match against a table of known technology favicon hashes.
  4. Optionally construct a Shodan dork: ``http.favicon.hash:<hash>``
     to find related infrastructure exposed on the internet.

Reference hashes from:
  - https://github.com/sansatart/scrapts/blob/master/shodan-favicon-hashes.csv
  - https://github.com/m4ll0k/FavFreak
  - https://github.com/devanshbatham/FavFreak
"""
import re
import base64
import logging
import time
from urllib.parse import urljoin, urlparse
from datetime import datetime
from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# ── MurmurHash3 32-bit (pure Python, matches mmh3 library output) ─────────

def _mmh3_32(data: bytes, seed: int = 0) -> int:  # noqa: C901
    """Pure-Python MurmurHash3 32-bit (signed).  Matches mmh3.hash()."""
    length = len(data)
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h1 = seed

    roundedEnd = (length & 0xFFFFFFFC)
    for i in range(0, roundedEnd, 4):
        k1 = (
            (data[i] & 0xFF)
            | ((data[i + 1] & 0xFF) << 8)
            | ((data[i + 2] & 0xFF) << 16)
            | ((data[i + 3] & 0xFF) << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 0x03
    if tail >= 3:
        k1 ^= (data[roundedEnd + 2] & 0xFF) << 16
    if tail >= 2:
        k1 ^= (data[roundedEnd + 1] & 0xFF) << 8
    if tail >= 1:
        k1 ^= data[roundedEnd] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit
    if h1 > 0x7FFFFFFF:
        h1 -= 0x100000000
    return h1


# ── Known favicon hashes → technology mapping ─────────────────────────────
# Format: hash_value: {'name': '...', 'category': '...', 'version': '...'}
KNOWN_FAVICON_HASHES: dict[int, dict] = {
    # Web servers / proxies
    -1146551624: {'name': 'Apache HTTP Server', 'category': 'server'},
    116323821:   {'name': 'Apache Tomcat', 'category': 'server'},
    1486527924:  {'name': 'Nginx', 'category': 'server'},
    -1708793473: {'name': 'Microsoft IIS', 'category': 'server'},
    -737603969:  {'name': 'F5 BIG-IP', 'category': 'network'},
    # Frameworks / CMS
    -875313221:  {'name': 'phpMyAdmin', 'category': 'database-admin'},
    1329373159:  {'name': 'WordPress', 'category': 'cms'},
    1110885752:  {'name': 'Joomla', 'category': 'cms'},
    -271808529:  {'name': 'Drupal', 'category': 'cms'},
    # Security appliances
    -635860769:  {'name': 'Palo Alto Networks', 'category': 'network-security'},
    1192602062:  {'name': 'Fortinet FortiGate', 'category': 'network-security'},
    -1419044765: {'name': 'Cisco ASA', 'category': 'network-security'},
    -1024724715: {'name': 'SonicWall', 'category': 'network-security'},
    708578631:   {'name': 'Juniper Networks', 'category': 'network'},
    -1501121799: {'name': 'Citrix NetScaler/ADC', 'category': 'network'},
    1109888028:  {'name': 'Pulse Secure VPN', 'category': 'vpn'},
    -1028328174: {'name': 'GlobalProtect (Palo Alto VPN)', 'category': 'vpn'},
    # Developer tools / monitoring
    -1559180916: {'name': 'Grafana', 'category': 'monitoring'},
    -373985000:  {'name': 'Kibana', 'category': 'monitoring'},
    -1548812825: {'name': 'Prometheus', 'category': 'monitoring'},
    116489023:   {'name': 'Jenkins', 'category': 'ci-cd'},
    -1325557794: {'name': 'GitLab', 'category': 'devtools'},
    -1609788816: {'name': 'Jira', 'category': 'project-management'},
    -1459055056: {'name': 'Confluence', 'category': 'cms'},
    -916816821:  {'name': 'SonarQube', 'category': 'devtools'},
    -1148551621: {'name': 'Vault (HashiCorp)', 'category': 'security'},
    -942555343:  {'name': 'Consul (HashiCorp)', 'category': 'infrastructure'},
    # Cloud / managed services
    708578631:   {'name': 'AWS Management Console', 'category': 'cloud'},
    -1776795908: {'name': 'Azure Portal', 'category': 'cloud'},
    -1541129052: {'name': 'Google Cloud Console', 'category': 'cloud'},
    # Database management
    -819547493:  {'name': 'MongoDB Admin', 'category': 'database-admin'},
    135414490:   {'name': 'Elasticsearch (Kopf/Cerebro)', 'category': 'search-engine'},
    # Authentication / IAM
    -1066844152: {'name': 'Okta', 'category': 'auth'},
    468880286:   {'name': 'Auth0', 'category': 'auth'},
    596580: {'name': 'Keycloak', 'category': 'auth'},
    # E-commerce
    -1095536866: {'name': 'Magento Admin', 'category': 'ecommerce'},
    1321160922:  {'name': 'Shopify Admin', 'category': 'ecommerce'},
    # C2 / Malware (for threat intelligence)
    -1438657642: {'name': 'Cobalt Strike (default)', 'category': 'c2-framework'},
    -1796420229: {'name': 'Metasploit Framework', 'category': 'c2-framework'},
    1109331916:  {'name': 'Sliver C2', 'category': 'c2-framework'},
    # IoT / Embedded
    -1023854774: {'name': 'Ubiquiti UniFi', 'category': 'iot'},
    -1553752478: {'name': 'MikroTik RouterOS', 'category': 'iot'},
    -2024557555: {'name': 'D-Link Router', 'category': 'iot'},
    1745542116:  {'name': 'Hikvision Camera', 'category': 'iot'},
}

# ── HTML favicon link extraction regex ───────────────────────────────────
_FAVICON_RE = re.compile(
    r'<link[^>]+rel=["\'](?:shortcut icon|icon|apple-touch-icon)["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _compute_favicon_hash(content: bytes) -> int:
    """Compute Shodan-compatible favicon hash (base64 encode then mmh3)."""
    b64 = base64.encodebytes(content)
    return _mmh3_32(b64)


def run_favicon_hash(
    target_url: str,
    depth: str = 'medium',
    make_request_fn=None,
    response_body: str = '',
) -> dict:
    """
    Fingerprint target via favicon hash.

    Args:
        target_url:      Full URL of the target home page.
        depth:           Scan depth.
        make_request_fn: Optional HTTP request function.
        response_body:   Pre-fetched homepage body (to extract favicon links).

    Returns:
        Standardised result dict with extra keys:
            ``favicon_hash``   : int | None
            ``favicon_url``    : str | None
            ``technology``     : dict | None  — matched technology info
            ``shodan_dork``    : str          — Shodan query
    """
    start = time.time()
    result = create_result('favicon_hash', target_url)
    result['favicon_hash'] = None
    result['favicon_url'] = None
    result['technology'] = None
    result['shodan_dork'] = ''

    if not make_request_fn:
        return finalize_result(result, start)

    parsed = urlparse(target_url)
    base = f'{parsed.scheme}://{parsed.netloc}'

    # ── Collect favicon URLs to try ───────────────────────────────────────
    favicon_urls = [urljoin(base, '/favicon.ico')]

    # Extract linked favicons from HTML
    if response_body:
        for href in _FAVICON_RE.findall(response_body):
            if not href.startswith('data:'):
                favicon_urls.insert(0, urljoin(base, href))

    result['stats']['total_checks'] = len(favicon_urls)
    favicon_content: bytes | None = None
    used_url: str | None = None

    for fav_url in favicon_urls:
        try:
            resp = make_request_fn('GET', fav_url, timeout=8)
            if resp and resp.status_code == 200 and resp.content:
                ct = resp.headers.get('Content-Type', '').lower()
                # Accept image types or unknown (some servers omit Content-Type)
                if 'text/html' not in ct:
                    favicon_content = resp.content
                    used_url = fav_url
                    result['stats']['successful_checks'] += 1
                    break
        except Exception as exc:
            result['errors'].append(f'Failed to fetch {fav_url}: {exc}')

    if not favicon_content:
        logger.debug('No favicon found for %s', target_url)
        return finalize_result(result, start)

    # ── Hash computation ──────────────────────────────────────────────────
    fav_hash = _compute_favicon_hash(favicon_content)
    result['favicon_hash'] = fav_hash
    result['favicon_url'] = used_url
    result['shodan_dork'] = f'http.favicon.hash:{fav_hash}'

    # ── Known hash matching ───────────────────────────────────────────────
    tech = KNOWN_FAVICON_HASHES.get(fav_hash)
    if tech:
        result['technology'] = tech
        severity = 'high' if tech.get('category') == 'c2-framework' else 'info'
        add_finding(result, {
            'type': 'favicon_match',
            'favicon_url': used_url,
            'favicon_hash': fav_hash,
            'technology': tech,
            'shodan_dork': result['shodan_dork'],
            'description': (
                f'Favicon hash {fav_hash} matches {tech["name"]} '
                f'({tech["category"]}). '
                f'Shodan dork: {result["shodan_dork"]}'
            ),
            'severity': severity,
        })
        logger.info(
            'Favicon match: %s → %s (%s)', target_url, tech['name'], fav_hash,
        )

        if tech.get('category') == 'c2-framework':
            add_finding(result, {
                'type': 'c2_framework_detected',
                'technology': tech['name'],
                'favicon_hash': fav_hash,
                'description': (
                    f'ALERT: Favicon hash matches known C2 framework '
                    f'({tech["name"]}). This may indicate a compromised server '
                    f'or an attacker-controlled infrastructure.'
                ),
                'severity': 'critical',
            })
    else:
        add_finding(result, {
            'type': 'favicon_unknown',
            'favicon_url': used_url,
            'favicon_hash': fav_hash,
            'shodan_dork': result['shodan_dork'],
            'description': (
                f'Favicon hash {fav_hash} — no match in known hash database. '
                f'Search Shodan: {result["shodan_dork"]}'
            ),
            'severity': 'info',
        })
        logger.debug('Favicon hash %d — no match for %s', fav_hash, target_url)

    result['metadata']['completed_at'] = datetime.utcnow().isoformat()
    return finalize_result(result, start)
