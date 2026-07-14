"""
VirusTotal Intelligence Module.

Queries VirusTotal API v3 for:
- Subdomain enumeration
- Domain reputation and category
- Passive DNS records
- Communicating and referencing files

Requires VT_API_KEY environment variable.
"""
import logging
import time
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

VT_API_BASE = 'https://www.virustotal.com/api/v3'
REQUEST_TIMEOUT = 15


def _get_api_key() -> str:
    """Retrieve VirusTotal API key."""
    try:
        from django.conf import settings
        return getattr(settings, 'VT_API_KEY', '') or ''
    except Exception:
        import os
        return os.getenv('VT_API_KEY', '')


def run_vt_intel(target: str, *, depth: str = 'medium',
                 make_request_fn=None) -> Optional[dict]:
    """Query VirusTotal for domain intelligence.

    Args:
        target: Target URL or domain.
        depth: Scan depth.

    Returns:
        Result dict with findings, or None if no API key.
    """
    api_key = _get_api_key()
    if not api_key:
        logger.debug('VirusTotal: No VT_API_KEY configured, skipping')
        return None

    start_time = time.time()
    result = {
        'module': 'vt_intel',
        'findings': [],
        'subdomains': [],
        'dns_records': [],
        'reputation': {},
        'errors': [],
        'stats': {'queries': 0, 'subdomains_found': 0},
    }

    hostname = urlparse(target).hostname or target
    headers = {'x-apikey': api_key}

    _get_domain_report(hostname, headers, result)
    _get_subdomains(hostname, headers, result, depth)
    _get_dns_resolutions(hostname, headers, result, depth)

    result['stats']['duration_seconds'] = round(time.time() - start_time, 3)
    return result


def _get_domain_report(hostname: str, headers: dict, result: dict):
    """Fetch domain reputation report."""
    try:
        resp = requests.get(
            f'{VT_API_BASE}/domains/{hostname}',
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json().get('data', {})
            attrs = data.get('attributes', {})

            analysis = attrs.get('last_analysis_stats', {})
            result['reputation'] = {
                'malicious': analysis.get('malicious', 0),
                'suspicious': analysis.get('suspicious', 0),
                'harmless': analysis.get('harmless', 0),
                'undetected': analysis.get('undetected', 0),
                'categories': attrs.get('categories', {}),
                'registrar': attrs.get('registrar', ''),
                'creation_date': attrs.get('creation_date', 0),
                'reputation_score': attrs.get('reputation', 0),
            }

            if analysis.get('malicious', 0) > 0:
                result['findings'].append({
                    'type': 'malicious_domain',
                    'malicious_count': analysis['malicious'],
                    'source': 'virustotal',
                    'severity': 'high',
                })

            if analysis.get('suspicious', 0) > 0:
                result['findings'].append({
                    'type': 'suspicious_domain',
                    'suspicious_count': analysis['suspicious'],
                    'source': 'virustotal',
                    'severity': 'medium',
                })

        elif resp.status_code == 401:
            result['errors'].append('Invalid VirusTotal API key')
        elif resp.status_code == 429:
            result['errors'].append('VirusTotal API rate limit exceeded')
        elif resp.status_code != 404:
            result['errors'].append(f'VT domain report error {resp.status_code}')

    except requests.RequestException as e:
        result['errors'].append(f'VT domain report failed: {str(e)}')


def _get_subdomains(hostname: str, headers: dict, result: dict, depth: str):
    """Enumerate subdomains via VirusTotal."""
    limit = 20 if depth == 'shallow' else 100
    try:
        resp = requests.get(
            f'{VT_API_BASE}/domains/{hostname}/subdomains',
            params={'limit': limit},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json()
            for item in data.get('data', []):
                subdomain = item.get('id', '')
                if subdomain:
                    result['subdomains'].append(subdomain)
                    result['findings'].append({
                        'type': 'subdomain',
                        'domain': subdomain,
                        'source': 'virustotal',
                    })
            result['stats']['subdomains_found'] = len(result['subdomains'])

        elif resp.status_code == 429:
            result['errors'].append('VT subdomains rate limit exceeded')
        elif resp.status_code not in (401, 404):
            result['errors'].append(f'VT subdomains error {resp.status_code}')

    except requests.RequestException as e:
        result['errors'].append(f'VT subdomain enum failed: {str(e)}')


def _get_dns_resolutions(hostname: str, headers: dict, result: dict, depth: str):
    """Fetch passive DNS records from VirusTotal."""
    limit = 10 if depth == 'shallow' else 40
    try:
        resp = requests.get(
            f'{VT_API_BASE}/domains/{hostname}/resolutions',
            params={'limit': limit},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json()
            for item in data.get('data', []):
                attrs = item.get('attributes', {})
                record = {
                    'ip': attrs.get('ip_address', ''),
                    'date': attrs.get('date', 0),
                    'resolver': attrs.get('host_name_last_analysis_stats', {}),
                }
                result['dns_records'].append(record)
                result['findings'].append({
                    'type': 'passive_dns',
                    'ip': attrs.get('ip_address', ''),
                    'source': 'virustotal',
                })

        elif resp.status_code == 429:
            result['errors'].append('VT DNS resolutions rate limit exceeded')
        elif resp.status_code not in (401, 404):
            result['errors'].append(f'VT DNS resolutions error {resp.status_code}')

    except requests.RequestException as e:
        result['errors'].append(f'VT DNS resolutions failed: {str(e)}')
