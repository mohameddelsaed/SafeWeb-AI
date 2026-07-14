"""
Censys Intelligence Module.

Queries Censys REST API for:
- Certificate search (find related domains/subdomains)
- Host enumeration and service discovery
- TLS certificate details

Requires CENSYS_API_ID and CENSYS_API_SECRET environment variables.
"""
import logging
import time
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

CENSYS_API_BASE = 'https://search.censys.io/api'
REQUEST_TIMEOUT = 15


def _get_credentials() -> tuple:
    """Retrieve Censys API credentials."""
    try:
        from django.conf import settings
        api_id = getattr(settings, 'CENSYS_API_ID', '') or ''
        api_secret = getattr(settings, 'CENSYS_API_SECRET', '') or ''
    except Exception:
        import os
        api_id = os.getenv('CENSYS_API_ID', '')
        api_secret = os.getenv('CENSYS_API_SECRET', '')
    return api_id, api_secret


def run_censys_intel(target: str, *, depth: str = 'medium',
                     make_request_fn=None) -> Optional[dict]:
    """Query Censys for certificate and host intelligence.

    Args:
        target: Target URL or domain.
        depth: Scan depth.

    Returns:
        Result dict with findings, or None if no API credentials.
    """
    api_id, api_secret = _get_credentials()
    if not api_id or not api_secret:
        logger.debug('Censys: No API credentials configured, skipping')
        return None

    start_time = time.time()
    result = {
        'module': 'censys_intel',
        'findings': [],
        'certificates': [],
        'hosts': [],
        'related_domains': [],
        'errors': [],
        'stats': {'queries': 0, 'certs_found': 0, 'hosts_found': 0},
    }

    hostname = urlparse(target).hostname or target
    auth = (api_id, api_secret)

    _search_certificates(hostname, auth, result, depth)
    _search_hosts(hostname, auth, result, depth)

    result['stats']['duration_seconds'] = round(time.time() - start_time, 3)
    return result


def _search_certificates(hostname: str, auth: tuple, result: dict, depth: str):
    """Search Censys certificate index for the domain."""
    try:
        query = f'parsed.names: {hostname}'
        per_page = 25 if depth == 'shallow' else 100

        resp = requests.get(
            f'{CENSYS_API_BASE}/v2/certificates/search',
            params={'q': query, 'per_page': min(per_page, 100)},
            auth=auth,
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json()
            hits = data.get('result', {}).get('hits', [])
            result['stats']['certs_found'] = len(hits)

            seen_domains = set()
            for hit in hits:
                cert_info = {
                    'fingerprint': hit.get('fingerprint_sha256', ''),
                    'issuer': hit.get('parsed', {}).get('issuer_dn', ''),
                    'subject': hit.get('parsed', {}).get('subject_dn', ''),
                    'names': hit.get('names', []),
                    'validity': {
                        'start': hit.get('parsed', {}).get('validity', {}).get('start', ''),
                        'end': hit.get('parsed', {}).get('validity', {}).get('end', ''),
                    },
                }
                result['certificates'].append(cert_info)

                # Extract related domains from certificate names
                for name in hit.get('names', []):
                    clean = name.lstrip('*.')
                    if clean not in seen_domains and clean != hostname:
                        seen_domains.add(clean)
                        result['related_domains'].append(clean)
                        result['findings'].append({
                            'type': 'related_domain',
                            'domain': clean,
                            'source': 'certificate',
                            'fingerprint': hit.get('fingerprint_sha256', '')[:16],
                        })

        elif resp.status_code == 401:
            result['errors'].append('Invalid Censys API credentials')
        elif resp.status_code == 429:
            result['errors'].append('Censys API rate limit exceeded')
        else:
            result['errors'].append(f'Censys certificate search error {resp.status_code}')

    except requests.RequestException as e:
        result['errors'].append(f'Censys certificate search failed: {str(e)}')


def _search_hosts(hostname: str, auth: tuple, result: dict, depth: str):
    """Search Censys host index."""
    try:
        query = f'services.tls.certificates.leaf.names: {hostname}'
        per_page = 25 if depth == 'shallow' else 100

        resp = requests.get(
            f'{CENSYS_API_BASE}/v2/hosts/search',
            params={'q': query, 'per_page': min(per_page, 100)},
            auth=auth,
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json()
            hits = data.get('result', {}).get('hits', [])
            result['stats']['hosts_found'] = len(hits)

            for hit in hits:
                host_info = {
                    'ip': hit.get('ip', ''),
                    'services': [],
                    'autonomous_system': hit.get('autonomous_system', {}),
                    'location': hit.get('location', {}),
                }

                for svc in hit.get('services', []):
                    host_info['services'].append({
                        'port': svc.get('port'),
                        'service_name': svc.get('service_name', ''),
                        'transport_protocol': svc.get('transport_protocol', ''),
                    })

                result['hosts'].append(host_info)
                result['findings'].append({
                    'type': 'discovered_host',
                    'ip': hit.get('ip', ''),
                    'services_count': len(hit.get('services', [])),
                    'source': 'censys',
                })

        elif resp.status_code == 401:
            result['errors'].append('Invalid Censys API credentials')
        elif resp.status_code == 429:
            result['errors'].append('Censys API rate limit exceeded')
        else:
            result['errors'].append(f'Censys host search error {resp.status_code}')

    except requests.RequestException as e:
        result['errors'].append(f'Censys host search failed: {str(e)}')
