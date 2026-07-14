"""
HTTP Probe — Probe discovered hosts for live HTTP(S) services.

Performs httpx-style probing: status codes, titles, server headers,
redirect chains, CDN detection, and admin panel heuristics.
"""
import logging
import re
import time

from ._base import create_result, add_finding, finalize_result, extract_hostname

logger = logging.getLogger(__name__)

# Ports to probe by depth
PORTS_SHALLOW = [80, 443]
PORTS_MEDIUM = [80, 443, 8080, 8443, 8000, 3000, 4443, 9443]
PORTS_DEEP = [80, 443, 8080, 8443, 8000, 3000, 4443, 9443, 8888, 9000, 9001, 10000]

# CDN detection headers
CDN_SIGNATURES = {
    'Cloudflare': ['CF-RAY', 'cf-cache-status'],
    'CloudFront': ['X-Amz-Cf-Id', 'X-Amz-Cf-Pop'],
    'Fastly': ['X-Served-By', 'X-Cache', 'Fastly-Debug-Digest'],
    'Azure CDN': ['X-Azure-Ref', 'X-MSEdge-Ref'],
    'GCP CDN': ['X-GUploader-UploadID', 'Via.*google'],
    'Akamai': ['X-Akamai-Transformed'],
}

# Admin panel heuristic keywords
ADMIN_KEYWORDS = ['admin', 'dashboard', 'login', 'panel', 'console', 'portal', 'manager']


def run_http_probe(target_url: str, hosts: list = None, depth: str = 'medium',
                   make_request_fn=None, **kwargs) -> dict:
    """
    Probe discovered hosts/subdomains for live HTTP(S) services.

    For each host: probe HTTP and HTTPS on multiple ports, capture
    status, title, server header, redirect chain, CDN, and admin hints.
    """
    start = time.time()
    result = create_result('http_probe', target_url, depth)
    hostname = extract_hostname(target_url)

    if not make_request_fn:
        result['errors'].append('No HTTP client provided')
        return finalize_result(result, start)

    # Build host list
    probe_hosts = [hostname] if hostname else []
    if hosts:
        probe_hosts.extend(h for h in hosts if h not in probe_hosts)

    if depth == 'shallow':
        ports = PORTS_SHALLOW
    elif depth == 'medium':
        ports = PORTS_MEDIUM
    else:
        ports = PORTS_DEEP

    live_services = []

    for host in probe_hosts[:50]:  # Cap to prevent abuse
        for port in ports:
            for scheme in ('https', 'http'):
                if port == 443 and scheme == 'http':
                    continue
                if port == 80 and scheme == 'https':
                    continue

                if port in (80, 443):
                    url = f'{scheme}://{host}/'
                else:
                    url = f'{scheme}://{host}:{port}/'

                result['stats']['total_checks'] += 1
                try:
                    response = make_request_fn('GET', url, timeout=8)
                    if not response:
                        result['stats']['failed_checks'] += 1
                        continue

                    result['stats']['successful_checks'] += 1
                    service_info = _analyze_response(response, url, host, port, scheme)
                    live_services.append(service_info)
                except Exception as exc:
                    result['stats']['failed_checks'] += 1
                    logger.debug('Probe failed for %s: %s', url, exc)

    # Summarize findings
    if live_services:
        add_finding(result, {
            'type': 'live_services',
            'severity': 'info',
            'title': f'{len(live_services)} live HTTP services found',
            'details': live_services,
        })

        # Flag admin panels
        admin_panels = [s for s in live_services if s.get('is_admin')]
        if admin_panels:
            add_finding(result, {
                'type': 'admin_panel',
                'severity': 'medium',
                'title': f'{len(admin_panels)} potential admin panel(s)',
                'details': admin_panels,
            })

        # List CDNs
        cdns = set()
        for s in live_services:
            if s.get('cdn'):
                cdns.add(s['cdn'])
        if cdns:
            add_finding(result, {
                'type': 'cdn_detected',
                'severity': 'info',
                'title': f'CDN detected: {", ".join(cdns)}',
                'details': list(cdns),
            })

    # ── External HTTP prober augmentation (httprobe) ──
    try:
        if hosts:
            from apps.scanning.engine.tools.wrappers.httprobe_wrapper import HttpprobeTool
            _hp = HttpprobeTool()
            if _hp.is_available():
                _known_urls = {s.get('url', '') for s in live_services}
                _extra_live = []
                for _tr in _hp.run('\n'.join(hosts)):
                    if _tr.host and _tr.host not in _known_urls:
                        _known_urls.add(_tr.host)
                        _extra_live.append(_tr.host)
                if _extra_live:
                    add_finding(result, {
                        'type': 'live_services',
                        'severity': 'info',
                        'title': f'httprobe: {len(_extra_live)} additional live HTTP service(s)',
                        'details': _extra_live,
                    })
    except Exception:
        pass

    return finalize_result(result, start)


def _analyze_response(response, url, host, port, scheme) -> dict:
    """Analyze an HTTP response and extract key metadata."""
    headers = dict(response.headers) if response.headers else {}
    body = response.text or ''

    # Extract title
    title = ''
    title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()[:200]

    # Server header
    server = headers.get('Server', headers.get('server', ''))

    # CDN detection
    cdn = None
    for cdn_name, signatures in CDN_SIGNATURES.items():
        for sig in signatures:
            for hdr_name in headers:
                if re.search(sig, hdr_name, re.IGNORECASE):
                    cdn = cdn_name
                    break
            if cdn:
                break
        if cdn:
            break

    # Admin panel heuristic
    is_admin = False
    title_lower = title.lower()
    for kw in ADMIN_KEYWORDS:
        if kw in title_lower:
            is_admin = True
            break

    # Detect technologies from headers
    technologies = []
    for hdr, val in headers.items():
        hdr_lower = hdr.lower()
        val_str = str(val)
        if 'x-powered-by' in hdr_lower:
            technologies.append(val_str)
        if 'x-aspnet-version' in hdr_lower:
            technologies.append(f'ASP.NET {val_str}')

    content_length = len(body)

    return {
        'url': url,
        'host': host,
        'port': port,
        'scheme': scheme,
        'status_code': response.status_code,
        'title': title,
        'server': server,
        'content_length': content_length,
        'cdn': cdn,
        'is_admin': is_admin,
        'technologies': technologies,
    }
