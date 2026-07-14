"""
Attack Surface Module — Comprehensive attack surface analysis.
Aggregates all recon findings to map the complete attack surface:
entry points, exposed services, trust boundaries, and data flows.
"""
import logging
import re
import time
from typing import Optional

from ._base import (
    create_result,
    add_finding,
    finalize_result,
)

logger = logging.getLogger(__name__)

# ── Severity weights for surface score calculation ─────────────────────────

_SEVERITY_WEIGHT = {
    'critical': 15,
    'high': 10,
    'medium': 5,
    'low': 2,
    'info': 1,
}

# Entry point detection patterns (applied against discovered paths/content)
_ENTRY_POINT_PATTERNS = [
    {'pattern': r'<form[^>]*action', 'type': 'form', 'method': 'POST'},
    {'pattern': r'/api/', 'type': 'api_endpoint', 'method': 'GET/POST'},
    {'pattern': r'/graphql', 'type': 'graphql', 'method': 'POST'},
    {'pattern': r'/ws|/websocket|/socket\.io', 'type': 'websocket', 'method': 'WS'},
    {'pattern': r'upload|file.*upload|multipart', 'type': 'file_upload', 'method': 'POST'},
    {'pattern': r'/oauth|/auth|/login|/signin', 'type': 'auth_endpoint', 'method': 'POST'},
    {'pattern': r'/register|/signup', 'type': 'registration', 'method': 'POST'},
    {'pattern': r'/reset|/forgot', 'type': 'password_reset', 'method': 'POST'},
    {'pattern': r'/admin|/dashboard|/panel', 'type': 'admin_panel', 'method': 'GET/POST'},
    {'pattern': r'/search|/query|\?q=', 'type': 'search', 'method': 'GET'},
    {'pattern': r'/webhook|/callback|/hook', 'type': 'webhook', 'method': 'POST'},
    {'pattern': r'\.xml$|\.json$|/feed|/rss', 'type': 'data_feed', 'method': 'GET'},
]


def _extract_entry_points(recon_data: dict, target_url: str) -> list:
    """Identify entry points from content discovery and other recon data."""
    entry_points = []
    seen = set()

    # From content discovery
    content = recon_data.get('content_discovery', {}) or {}
    paths = content.get('findings', content.get('discovered_paths', []))

    for item in paths if isinstance(paths, list) else []:
        path = item.get('path', item.get('url', '')) if isinstance(item, dict) else str(item)
        status = item.get('status_code', item.get('status', 200)) if isinstance(item, dict) else 200

        for ep in _ENTRY_POINT_PATTERNS:
            if re.search(ep['pattern'], path, re.I) and path not in seen:
                seen.add(path)
                entry_points.append({
                    'type': ep['type'],
                    'url': path,
                    'method': ep['method'],
                    'auth_required': ep['type'] in ('admin_panel', 'auth_endpoint'),
                    'status_code': status,
                })
                break

    # From API discovery
    api = recon_data.get('api_discovery', {}) or {}
    api_endpoints = api.get('findings', api.get('endpoints', []))
    for ep in api_endpoints if isinstance(api_endpoints, list) else []:
        url = ep.get('url', ep.get('path', '')) if isinstance(ep, dict) else str(ep)
        if url and url not in seen:
            seen.add(url)
            entry_points.append({
                'type': 'api_endpoint',
                'url': url,
                'method': ep.get('method', 'GET') if isinstance(ep, dict) else 'GET',
                'auth_required': False,
            })

    # From param discovery
    params = recon_data.get('param_discovery', {}) or {}
    param_findings = params.get('findings', params.get('parameters', []))
    for p in param_findings if isinstance(param_findings, list) else []:
        url = p.get('url', '') if isinstance(p, dict) else ''
        if url and url not in seen:
            seen.add(url)
            entry_points.append({
                'type': 'parameterized_endpoint',
                'url': url,
                'method': 'GET',
                'auth_required': False,
            })

    # Always include the target itself
    if target_url not in seen:
        entry_points.append({
            'type': 'main_target',
            'url': target_url,
            'method': 'GET',
            'auth_required': False,
        })

    return entry_points


def _extract_exposed_services(recon_data: dict) -> list:
    """Extract exposed services from port scanning and subdomain enumeration."""
    services = []
    seen = set()

    # From port scanning
    ports_data = recon_data.get('ports', {}) or {}
    open_ports = ports_data.get('findings', ports_data.get('open_ports', []))

    for port_info in open_ports if isinstance(open_ports, list) else []:
        port = port_info.get('port', 0) if isinstance(port_info, dict) else 0
        service = port_info.get('service', 'unknown') if isinstance(port_info, dict) else 'unknown'
        protocol = port_info.get('protocol', 'tcp') if isinstance(port_info, dict) else 'tcp'

        key = f"{port}:{protocol}"
        if key not in seen:
            seen.add(key)
            services.append({
                'service': service,
                'port': port,
                'protocol': protocol,
                'state': port_info.get('state', 'open') if isinstance(port_info, dict) else 'open',
            })

    # From subdomains
    subs = recon_data.get('subdomains', {}) or {}
    sub_list = subs.get('findings', subs.get('subdomains', []))
    for sub in sub_list if isinstance(sub_list, list) else []:
        name = sub.get('subdomain', sub.get('name', '')) if isinstance(sub, dict) else str(sub)
        if name and name not in seen:
            seen.add(name)
            services.append({
                'service': 'subdomain',
                'port': 443,
                'protocol': 'https',
                'hostname': name,
            })

    # From cloud detection
    cloud = recon_data.get('cloud', {}) or {}
    cloud_findings = cloud.get('findings', cloud.get('services', []))
    for svc in cloud_findings if isinstance(cloud_findings, list) else []:
        name = svc.get('service', svc.get('provider', '')) if isinstance(svc, dict) else str(svc)
        if name and name not in seen:
            seen.add(name)
            services.append({
                'service': f'cloud:{name}',
                'port': 443,
                'protocol': 'https',
            })

    return services


def _identify_trust_boundaries(recon_data: dict, entry_points: list) -> list:
    """Identify trust boundaries from the discovered infrastructure."""
    boundaries = []

    # External vs Internal boundary
    has_auth = any(ep.get('auth_required') for ep in entry_points)
    public_count = sum(1 for ep in entry_points if not ep.get('auth_required'))
    auth_count = sum(1 for ep in entry_points if ep.get('auth_required'))

    boundaries.append({
        'name': 'Internet → Application',
        'type': 'external',
        'public_endpoints': public_count,
        'description': f'{public_count} public entry points accessible without authentication',
    })

    if has_auth:
        boundaries.append({
            'name': 'Public → Authenticated',
            'type': 'authentication',
            'protected_endpoints': auth_count,
            'description': f'{auth_count} endpoints require authentication',
        })

    # WAF boundary
    waf = recon_data.get('waf', {}) or {}
    if waf.get('detected') or waf.get('findings'):
        boundaries.append({
            'name': 'Internet → WAF → Application',
            'type': 'waf',
            'description': 'WAF filtering layer detected between internet and application',
        })

    # CDN boundary
    techs = recon_data.get('technologies', {}) or {}
    tech_list = techs.get('technologies', techs.get('findings', []))
    for tech in tech_list if isinstance(tech_list, list) else []:
        cat = tech.get('category', '') if isinstance(tech, dict) else ''
        if re.search(r'cdn', cat, re.I):
            boundaries.append({
                'name': 'Internet → CDN → Origin',
                'type': 'cdn',
                'description': 'CDN edge caching layer detected in front of origin server',
            })
            break

    return boundaries


def _derive_attack_vectors(entry_points: list, services: list,
                           boundaries: list, recon_data: dict) -> list:
    """Derive possible attack vectors from the mapped surface."""
    vectors = []

    # Vector: Web application attacks via entry points
    form_eps = [ep for ep in entry_points if ep['type'] in ('form', 'search', 'registration')]
    if form_eps:
        vectors.append({
            'vector': 'Injection Attacks (SQLi / XSS / Command Injection)',
            'targets': [ep['url'] for ep in form_eps[:5]],
            'severity': 'high',
            'description': f'{len(form_eps)} input-accepting entry points identified',
        })

    # Vector: API abuse
    api_eps = [ep for ep in entry_points if ep['type'] in ('api_endpoint', 'graphql')]
    if api_eps:
        vectors.append({
            'vector': 'API Abuse (BOLA / Rate Limiting / Mass Assignment)',
            'targets': [ep['url'] for ep in api_eps[:5]],
            'severity': 'high',
            'description': f'{len(api_eps)} API endpoints discovered',
        })

    # Vector: Authentication attacks
    auth_eps = [ep for ep in entry_points if ep['type'] in ('auth_endpoint', 'password_reset')]
    if auth_eps:
        vectors.append({
            'vector': 'Authentication Attacks (Brute Force / Credential Stuffing)',
            'targets': [ep['url'] for ep in auth_eps[:5]],
            'severity': 'high',
            'description': f'{len(auth_eps)} authentication-related endpoints found',
        })

    # Vector: File upload exploitation
    upload_eps = [ep for ep in entry_points if ep['type'] == 'file_upload']
    if upload_eps:
        vectors.append({
            'vector': 'File Upload Exploitation (Web Shell / Malware)',
            'targets': [ep['url'] for ep in upload_eps[:5]],
            'severity': 'critical',
            'description': f'{len(upload_eps)} file upload entry points detected',
        })

    # Vector: Network-level attacks from open ports
    risky_ports = [s for s in services if isinstance(s.get('port'), int) and s['port'] not in (80, 443)]
    if risky_ports:
        vectors.append({
            'vector': 'Network Service Exploitation',
            'targets': [f"{s['service']}:{s['port']}" for s in risky_ports[:5]],
            'severity': 'medium',
            'description': f'{len(risky_ports)} non-standard ports/services exposed',
        })

    # Vector: Subdomain takeover
    sub_services = [s for s in services if s.get('service') == 'subdomain']
    if sub_services:
        vectors.append({
            'vector': 'Subdomain Takeover',
            'targets': [s.get('hostname', '') for s in sub_services[:5]],
            'severity': 'medium',
            'description': f'{len(sub_services)} subdomains found — potential takeover targets',
        })

    # Vector: Information leakage
    headers_data = recon_data.get('headers', {}) or {}
    if headers_data.get('findings') or headers_data.get('issues'):
        vectors.append({
            'vector': 'Information Disclosure',
            'targets': ['HTTP headers', 'Error pages', 'Source comments'],
            'severity': 'low',
            'description': 'Security header issues may leak server/framework information',
        })

    return vectors


def _calculate_surface_score(entry_points: list, services: list,
                             vectors: list, boundaries: list) -> int:
    """Calculate attack surface area score (0-100, higher = larger surface)."""
    score = 0

    # Entry points contribute
    score += min(len(entry_points) * 3, 25)

    # Services contribute
    score += min(len(services) * 4, 20)

    # Attack vectors weighted by severity
    for v in vectors:
        score += _SEVERITY_WEIGHT.get(v.get('severity', 'info'), 1)

    # Fewer trust boundaries = more exposure
    if len(boundaries) <= 1:
        score += 15
    elif len(boundaries) == 2:
        score += 8

    # Clamp
    return min(max(score, 0), 100)


def _generate_summary(entry_points: list, services: list,
                      vectors: list, surface_score: int) -> str:
    """Generate a human-readable summary of the attack surface."""
    risk = 'low'
    if surface_score >= 75:
        risk = 'critical'
    elif surface_score >= 50:
        risk = 'high'
    elif surface_score >= 25:
        risk = 'medium'

    return (
        f"Attack surface score: {surface_score}/100 ({risk} exposure). "
        f"Identified {len(entry_points)} entry point(s), "
        f"{len(services)} exposed service(s), and "
        f"{len(vectors)} potential attack vector(s)."
    )


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_attack_surface(target_url: str, recon_data: Optional[dict] = None) -> dict:
    """
    Map the complete attack surface by aggregating all recon findings.

    Args:
        target_url: The target URL being scanned.
        recon_data: Aggregated dict of all prior recon module results.

    Returns:
        Standardised result dict with legacy keys:
        ``entry_points``, ``exposed_services``, ``trust_boundaries``,
        ``attack_vectors``, ``surface_score``, ``summary``, ``issues``.
    """
    start = time.time()
    result = create_result('attack_surface', target_url)

    # Legacy keys
    result['entry_points'] = []
    result['exposed_services'] = []
    result['trust_boundaries'] = []
    result['attack_vectors'] = []
    result['surface_score'] = 0
    result['summary'] = ''
    result['issues'] = []

    if recon_data is None:
        recon_data = {}

    logger.info('Starting attack surface mapping for %s', target_url)

    try:
        # ── Phase 1: Enumerate entry points ────────────────────────────
        result['stats']['total_checks'] += 1
        try:
            entry_points = _extract_entry_points(recon_data, target_url)
            result['entry_points'] = entry_points
            result['stats']['successful_checks'] += 1
            for ep in entry_points:
                add_finding(result, {
                    'type': 'entry_point',
                    'subtype': ep['type'],
                    'url': ep['url'],
                    'method': ep['method'],
                    'auth_required': ep.get('auth_required', False),
                })
        except Exception as exc:
            logger.error('Entry point extraction failed: %s', exc)
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Entry point extraction: {exc}')

        # ── Phase 2: Enumerate exposed services ────────────────────────
        result['stats']['total_checks'] += 1
        try:
            services = _extract_exposed_services(recon_data)
            result['exposed_services'] = services
            result['stats']['successful_checks'] += 1
            for svc in services:
                add_finding(result, {
                    'type': 'exposed_service',
                    'service': svc['service'],
                    'port': svc['port'],
                    'protocol': svc['protocol'],
                })
        except Exception as exc:
            logger.error('Service extraction failed: %s', exc)
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Service extraction: {exc}')

        # ── Phase 3: Identify trust boundaries ─────────────────────────
        result['stats']['total_checks'] += 1
        try:
            boundaries = _identify_trust_boundaries(recon_data, result['entry_points'])
            result['trust_boundaries'] = boundaries
            result['stats']['successful_checks'] += 1
            for b in boundaries:
                add_finding(result, {
                    'type': 'trust_boundary',
                    'name': b['name'],
                    'boundary_type': b['type'],
                    'description': b['description'],
                })
        except Exception as exc:
            logger.error('Trust boundary identification failed: %s', exc)
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Trust boundary identification: {exc}')

        # ── Phase 4: Derive attack vectors ─────────────────────────────
        result['stats']['total_checks'] += 1
        try:
            vectors = _derive_attack_vectors(
                result['entry_points'], result['exposed_services'],
                result['trust_boundaries'], recon_data,
            )
            result['attack_vectors'] = vectors
            result['stats']['successful_checks'] += 1
            for v in vectors:
                add_finding(result, {
                    'type': 'attack_vector',
                    'vector': v['vector'],
                    'severity': v['severity'],
                    'targets': v.get('targets', []),
                    'description': v['description'],
                })
                result['issues'].append(
                    f"{v['severity'].upper()}: {v['vector']} — {v['description']}"
                )
        except Exception as exc:
            logger.error('Attack vector derivation failed: %s', exc)
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Attack vector derivation: {exc}')

        # ── Phase 5: Calculate surface score & summary ─────────────────
        result['stats']['total_checks'] += 1
        try:
            result['surface_score'] = _calculate_surface_score(
                result['entry_points'], result['exposed_services'],
                result['attack_vectors'], result['trust_boundaries'],
            )
            result['summary'] = _generate_summary(
                result['entry_points'], result['exposed_services'],
                result['attack_vectors'], result['surface_score'],
            )
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            logger.error('Score calculation failed: %s', exc)
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Score calculation: {exc}')

    except Exception as exc:
        msg = f'Attack surface mapping error: {exc}'
        logger.error(msg, exc_info=True)
        result['errors'].append(msg)

    logger.info(
        'Attack surface mapping complete for %s — score %d/100, %d entry points, %d services',
        target_url, result['surface_score'],
        len(result['entry_points']), len(result['exposed_services']),
    )

    return finalize_result(result, start)
