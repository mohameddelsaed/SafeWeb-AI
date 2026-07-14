"""
Shodan Intelligence Module.

Queries Shodan REST API for target IP intelligence:
- Exposed ports and services
- Known vulnerabilities (CVEs)
- SSL/TLS certificate info
- Organization, ISP, ASN data
- HTTP component fingerprinting

Requires SHODAN_API_KEY environment variable.
"""
import logging
import time
from typing import Optional
from urllib.parse import quote_plus

import requests

logger = logging.getLogger(__name__)

# Shodan API base
SHODAN_API_BASE = 'https://api.shodan.io'
REQUEST_TIMEOUT = 15


def _get_api_key() -> str:
    """Retrieve Shodan API key from Django settings or env."""
    try:
        from django.conf import settings
        return getattr(settings, 'SHODAN_API_KEY', '') or ''
    except Exception:
        import os
        return os.getenv('SHODAN_API_KEY', '')


def run_shodan_intel(target: str, *, ip_addresses: list = None,
                     depth: str = 'medium',
                     make_request_fn=None) -> Optional[dict]:
    """Query Shodan for intelligence on the target.

    Args:
        target: Target URL or domain.
        ip_addresses: List of resolved IPs (from DNS recon).
        depth: Scan depth.
        make_request_fn: Optional custom request function.

    Returns:
        Result dict with findings, or None if no API key.
    """
    api_key = _get_api_key()
    if not api_key:
        logger.debug('Shodan: No API key configured, skipping')
        return None

    start_time = time.time()
    result = {
        'module': 'shodan_intel',
        'findings': [],
        'hosts': [],
        'ports': [],
        'vulns': [],
        'ssl_info': [],
        'errors': [],
        'stats': {'queries': 0, 'hosts_found': 0},
    }

    ips = ip_addresses or []
    if not ips:
        # Try to extract from target
        from urllib.parse import urlparse
        hostname = urlparse(target).hostname or target
        ips = [hostname]

    for ip in ips[:5]:  # Limit to 5 IPs
        _query_host(ip, api_key, result, depth)

    # DNS lookup on domain
    from urllib.parse import urlparse
    hostname = urlparse(target).hostname or target
    _query_dns(hostname, api_key, result)

    result['stats']['duration_seconds'] = round(time.time() - start_time, 3)
    return result


def _query_host(ip: str, api_key: str, result: dict, depth: str):
    """Query Shodan /shodan/host/{ip} endpoint."""
    try:
        resp = requests.get(
            f'{SHODAN_API_BASE}/shodan/host/{quote_plus(ip)}',
            params={'key': api_key, 'minify': depth != 'deep'},
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json()
            host_info = {
                'ip': ip,
                'org': data.get('org', ''),
                'isp': data.get('isp', ''),
                'asn': data.get('asn', ''),
                'os': data.get('os', ''),
                'ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'country': data.get('country_code', ''),
                'city': data.get('city', ''),
                'last_update': data.get('last_update', ''),
            }
            result['hosts'].append(host_info)
            result['stats']['hosts_found'] += 1

            # Collect ports
            for port in data.get('ports', []):
                if port not in result['ports']:
                    result['ports'].append(port)

            # Collect vulnerabilities
            for vuln in data.get('vulns', []):
                if vuln not in result['vulns']:
                    result['vulns'].append(vuln)
                    result['findings'].append({
                        'type': 'known_vulnerability',
                        'ip': ip,
                        'cve': vuln,
                        'severity': 'high',
                    })

            # Collect SSL info from services
            for service in data.get('data', []):
                if 'ssl' in service:
                    ssl = service['ssl']
                    result['ssl_info'].append({
                        'ip': ip,
                        'port': service.get('port'),
                        'issuer': ssl.get('cert', {}).get('issuer', {}),
                        'expires': ssl.get('cert', {}).get('expires', ''),
                        'cipher': ssl.get('cipher', {}),
                    })

                # Add service finding
                result['findings'].append({
                    'type': 'exposed_service',
                    'ip': ip,
                    'port': service.get('port'),
                    'transport': service.get('transport', 'tcp'),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'banner': (service.get('data', '') or '')[:200],
                })

        elif resp.status_code == 404:
            logger.debug('Shodan: No data for IP %s', ip)
        elif resp.status_code == 401:
            result['errors'].append('Invalid Shodan API key')
        else:
            result['errors'].append(f'Shodan API error {resp.status_code} for {ip}')

    except requests.RequestException as e:
        result['errors'].append(f'Shodan request failed for {ip}: {str(e)}')


def _query_dns(hostname: str, api_key: str, result: dict):
    """Query Shodan /dns/resolve for hostname."""
    try:
        resp = requests.get(
            f'{SHODAN_API_BASE}/dns/resolve',
            params={'hostnames': hostname, 'key': api_key},
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json()
            if hostname in data and data[hostname]:
                result['findings'].append({
                    'type': 'dns_resolution',
                    'hostname': hostname,
                    'ip': data[hostname],
                })
    except requests.RequestException as e:
        result['errors'].append(f'Shodan DNS resolve failed: {str(e)}')
