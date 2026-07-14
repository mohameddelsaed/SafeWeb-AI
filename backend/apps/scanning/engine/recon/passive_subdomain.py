"""
Passive Subdomain Discovery — Multi-source passive subdomain enumeration.

Queries 8+ free OSINT sources for subdomains WITHOUT sending any traffic
to the target:

    1. crt.sh (Certificate Transparency)
    2. HackerTarget
    3. AlienVault OTX
    4. ThreatCrowd
    5. URLScan.io
    6. Anubis DB
    7. RapidDNS
    8. Omnisint/Sonar (Project Discovery Chaos)

Each source is queried concurrently, results are deduplicated and merged.

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# Timeout for each source query
_SOURCE_TIMEOUT = 15

# Max concurrent source queries
_MAX_SOURCE_WORKERS = 8


# ── Individual Source Fetchers ────────────────────────────────────────────────

def _query_crtsh(domain: str) -> set[str]:
    """Query crt.sh Certificate Transparency logs."""
    subs = set()
    try:
        url = f'https://crt.sh/?q=%.{quote(domain)}&output=json'
        resp = requests.get(url, timeout=_SOURCE_TIMEOUT, verify=True)
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get('name_value', '')
                for part in name.split('\n'):
                    part = part.strip().lower()
                    if part.endswith(f'.{domain}') or part == domain:
                        # Remove wildcard prefix
                        part = part.lstrip('*.')
                        if part:
                            subs.add(part)
    except Exception as e:
        logger.debug('crt.sh query failed: %s', e)
    return subs


def _query_hackertarget(domain: str) -> set[str]:
    """Query HackerTarget free API."""
    subs = set()
    try:
        url = f'https://api.hackertarget.com/hostsearch/?q={quote(domain)}'
        resp = requests.get(url, timeout=_SOURCE_TIMEOUT)
        if resp.status_code == 200 and 'error' not in resp.text.lower():
            for line in resp.text.strip().splitlines():
                parts = line.split(',')
                if parts:
                    host = parts[0].strip().lower()
                    if host.endswith(f'.{domain}') or host == domain:
                        subs.add(host)
    except Exception as e:
        logger.debug('HackerTarget query failed: %s', e)
    return subs


def _query_alienvault(domain: str) -> set[str]:
    """Query AlienVault OTX passive DNS."""
    subs = set()
    try:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns'
        resp = requests.get(url, timeout=_SOURCE_TIMEOUT, headers={
            'User-Agent': 'SafeWeb-AI/2.0',
        })
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get('passive_dns', []):
                host = entry.get('hostname', '').strip().lower()
                if host.endswith(f'.{domain}') or host == domain:
                    subs.add(host)
    except Exception as e:
        logger.debug('AlienVault query failed: %s', e)
    return subs


def _query_threatcrowd(domain: str) -> set[str]:
    """Query ThreatCrowd API."""
    subs = set()
    try:
        url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={quote(domain)}'
        resp = requests.get(url, timeout=_SOURCE_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get('subdomains', []):
                host = sub.strip().lower()
                if host.endswith(f'.{domain}') or host == domain:
                    subs.add(host)
    except Exception as e:
        logger.debug('ThreatCrowd query failed: %s', e)
    return subs


def _query_urlscan(domain: str) -> set[str]:
    """Query URLScan.io for subdomains seen in scans."""
    subs = set()
    try:
        url = f'https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=1000'
        resp = requests.get(url, timeout=_SOURCE_TIMEOUT, headers={
            'User-Agent': 'SafeWeb-AI/2.0',
        })
        if resp.status_code == 200:
            data = resp.json()
            for result in data.get('results', []):
                page = result.get('page', {})
                host = page.get('domain', '').strip().lower()
                if host.endswith(f'.{domain}') or host == domain:
                    subs.add(host)
                # Also check task.domain
                task_domain = result.get('task', {}).get('domain', '').strip().lower()
                if task_domain.endswith(f'.{domain}') or task_domain == domain:
                    subs.add(task_domain)
    except Exception as e:
        logger.debug('URLScan query failed: %s', e)
    return subs


def _query_anubis(domain: str) -> set[str]:
    """Query Anubis DB API."""
    subs = set()
    try:
        url = f'https://jldc.me/anubis/subdomains/{quote(domain)}'
        resp = requests.get(url, timeout=_SOURCE_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for host in data:
                    host = host.strip().lower()
                    if host.endswith(f'.{domain}') or host == domain:
                        subs.add(host)
    except Exception as e:
        logger.debug('Anubis query failed: %s', e)
    return subs


def _query_rapiddns(domain: str) -> set[str]:
    """Scrape RapidDNS.io for subdomain data."""
    subs = set()
    try:
        url = f'https://rapiddns.io/subdomain/{quote(domain)}?full=1#result'
        resp = requests.get(url, timeout=_SOURCE_TIMEOUT, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        })
        if resp.status_code == 200:
            # Extract subdomains from HTML table
            pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)*' + re.escape(domain)
            re.findall(pattern, resp.text)
            # More robust regex
            full_pattern = rf'([\w.-]+\.{re.escape(domain)})'
            for match in re.findall(full_pattern, resp.text):
                host = match.strip().lower()
                subs.add(host)
    except Exception as e:
        logger.debug('RapidDNS query failed: %s', e)
    return subs


def _query_certspotter(domain: str) -> set[str]:
    """Query Cert Spotter API (SSLMate)."""
    subs = set()
    try:
        url = f'https://api.certspotter.com/v1/issuances?domain={quote(domain)}&include_subdomains=true&expand=dns_names'
        resp = requests.get(url, timeout=_SOURCE_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for cert in data:
                for name in cert.get('dns_names', []):
                    host = name.strip().lower().lstrip('*.')
                    if host.endswith(f'.{domain}') or host == domain:
                        subs.add(host)
    except Exception as e:
        logger.debug('CertSpotter query failed: %s', e)
    return subs


# ── Source Registry ───────────────────────────────────────────────────────────

_SOURCES = {
    'crt.sh':         _query_crtsh,
    'hackertarget':   _query_hackertarget,
    'alienvault':     _query_alienvault,
    'threatcrowd':    _query_threatcrowd,
    'urlscan':        _query_urlscan,
    'anubis':         _query_anubis,
    'rapiddns':       _query_rapiddns,
    'certspotter':    _query_certspotter,
}


# ── Main Entry Point ─────────────────────────────────────────────────────────

def run_passive_subdomain(target_url: str, depth: str = 'medium') -> dict:
    """
    Perform passive subdomain discovery from multiple OSINT sources.

    Returns standardised dict plus legacy keys:
        subdomains, source_counts, total_unique
    """
    start = time.time()
    result = create_result('passive_subdomain', target_url, depth)
    hostname = extract_hostname(target_url)
    domain = extract_root_domain(hostname)

    if not domain:
        result['errors'].append('Could not extract domain from target URL')
        return finalize_result(result, start)

    # Select sources based on depth
    if depth == 'shallow':
        selected_sources = {'crt.sh': _SOURCES['crt.sh'], 'hackertarget': _SOURCES['hackertarget']}
    elif depth == 'medium':
        selected_sources = {k: v for k, v in _SOURCES.items()
                           if k in ('crt.sh', 'hackertarget', 'alienvault', 'certspotter', 'anubis')}
    else:  # deep
        selected_sources = dict(_SOURCES)

    # Query all sources concurrently
    all_subdomains: set[str] = set()
    source_counts: dict[str, int] = {}

    with ThreadPoolExecutor(max_workers=_MAX_SOURCE_WORKERS) as pool:
        futures = {
            pool.submit(fn, domain): name
            for name, fn in selected_sources.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                subs = future.result()
                source_counts[name] = len(subs)
                all_subdomains |= subs
                result['stats']['successful_checks'] += 1
            except Exception as e:
                source_counts[name] = 0
                result['stats']['failed_checks'] += 1
                result['errors'].append(f'{name}: {str(e)}')
            result['stats']['total_checks'] += 1

    # Sort and build findings
    sorted_subs = sorted(all_subdomains)
    for sub in sorted_subs:
        add_finding(result, {
            'type': 'subdomain',
            'subdomain': sub,
            'source': 'passive',
        })

    # Summary finding
    add_finding(result, {
        'type': 'summary',
        'total_unique': len(sorted_subs),
        'sources_queried': len(selected_sources),
        'sources_successful': result['stats']['successful_checks'],
        'source_breakdown': source_counts,
    })

    # Legacy keys
    result['subdomains'] = sorted_subs
    result['source_counts'] = source_counts
    result['total_unique'] = len(sorted_subs)

    logger.info(
        'Passive subdomain discovery: %d unique subdomains from %d sources for %s',
        len(sorted_subs), len(selected_sources), domain,
    )

    return finalize_result(result, start)
