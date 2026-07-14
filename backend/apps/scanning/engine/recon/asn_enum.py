"""
ASN Enumeration Module — Discover IP ranges and domains owned by an organization.

Uses public BGP data sources (RIPEstat, bgpview.io) to:
  1. Find ASNs associated with an organization name
  2. Enumerate IP prefixes announced by those ASNs
  3. Reverse DNS on sampled IPs to discover domain names

This is used by the wide-scope resolver for company-level pentesting.
"""
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

_BGPVIEW_SEARCH_URL = 'https://api.bgpview.io/search?query_term={query}'
_BGPVIEW_ASN_PREFIXES_URL = 'https://api.bgpview.io/asn/{asn}/prefixes'
_REQUEST_TIMEOUT = 15
_MAX_REVERSE_DNS_IPS = 100
_REVERSE_DNS_WORKERS = 20


def run_asn_enum(company: str) -> dict:
    """Main entry: discover domains owned by a company via ASN enumeration.

    Returns:
        dict with 'domains' (list[str]), 'asns' (list), 'prefixes' (list),
        'errors' (list[str])
    """
    result = {
        'domains': [],
        'asns': [],
        'prefixes': [],
        'errors': [],
    }

    if not company or not company.strip():
        result['errors'].append('Empty company name')
        return result

    try:
        import requests
    except ImportError:
        result['errors'].append('requests library not available')
        return result

    # Step 1: Search for ASNs by company name
    asns = _search_asns(company, requests)
    result['asns'] = asns
    if not asns:
        logger.info('No ASNs found for company: %s', company)
        return result

    logger.info('Found %d ASNs for %s: %s', len(asns), company,
                [a['asn'] for a in asns])

    # Step 2: Get IP prefixes for each ASN
    all_prefixes = []
    for asn_info in asns[:5]:  # Cap at 5 ASNs
        prefixes = _get_asn_prefixes(asn_info['asn'], requests)
        all_prefixes.extend(prefixes)
    result['prefixes'] = all_prefixes

    if not all_prefixes:
        logger.info('No IP prefixes found for ASNs of %s', company)
        return result

    logger.info('Found %d IP prefixes for %s', len(all_prefixes), company)

    # Step 3: Sample IPs from prefixes and do reverse DNS
    sample_ips = _sample_ips_from_prefixes(all_prefixes, max_ips=_MAX_REVERSE_DNS_IPS)
    domains = _reverse_dns_bulk(sample_ips)
    result['domains'] = sorted(set(domains))

    logger.info('ASN enum for %s: %d domains from %d sampled IPs',
                company, len(result['domains']), len(sample_ips))
    return result


def _search_asns(company: str, requests_mod) -> list[dict]:
    """Search BGPView for ASNs matching the company name."""
    url = _BGPVIEW_SEARCH_URL.format(query=company.replace(' ', '+'))
    try:
        resp = requests_mod.get(url, timeout=_REQUEST_TIMEOUT, headers={
            'User-Agent': 'SafeWeb-AI Security Scanner',
        })
        resp.raise_for_status()
        data = resp.json()

        asns = []
        for item in data.get('data', {}).get('asns', []):
            asns.append({
                'asn': item.get('asn'),
                'name': item.get('name', ''),
                'description': item.get('description', ''),
                'country_code': item.get('country_code', ''),
            })
        return asns[:10]  # Cap at 10 ASNs

    except Exception as exc:
        logger.warning('BGPView ASN search failed for %s: %s', company, exc)
        return []


def _get_asn_prefixes(asn: int, requests_mod) -> list[dict]:
    """Get IPv4/IPv6 prefixes announced by an ASN."""
    url = _BGPVIEW_ASN_PREFIXES_URL.format(asn=asn)
    try:
        resp = requests_mod.get(url, timeout=_REQUEST_TIMEOUT, headers={
            'User-Agent': 'SafeWeb-AI Security Scanner',
        })
        resp.raise_for_status()
        data = resp.json()

        prefixes = []
        for prefix in data.get('data', {}).get('ipv4_prefixes', []):
            prefixes.append({
                'prefix': prefix.get('prefix', ''),
                'asn': asn,
                'name': prefix.get('name', ''),
                'description': prefix.get('description', ''),
            })
        return prefixes[:50]  # Cap at 50 prefixes per ASN

    except Exception as exc:
        logger.warning('BGPView prefix lookup failed for ASN %s: %s', asn, exc)
        return []


def _sample_ips_from_prefixes(prefixes: list[dict], max_ips: int = 100) -> list[str]:
    """Sample representative IPs from CIDR prefixes for reverse DNS."""
    import ipaddress
    ips = []

    for prefix_info in prefixes:
        prefix_str = prefix_info.get('prefix', '')
        if not prefix_str:
            continue
        try:
            network = ipaddress.ip_network(prefix_str, strict=False)
            # Sample first few usable IPs from each prefix
            count = 0
            for ip in network.hosts():
                if count >= 3:  # 3 IPs per prefix
                    break
                ips.append(str(ip))
                count += 1
                if len(ips) >= max_ips:
                    return ips
        except (ValueError, TypeError):
            continue

    return ips


def _reverse_dns_bulk(ips: list[str]) -> list[str]:
    """Perform reverse DNS lookups on a list of IPs concurrently."""
    domains = []

    def _lookup(ip: str) -> str | None:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            # Filter out generic PTR records
            if hostname and not re.match(r'^[\d\-]+\.', hostname):
                # Extract root-ish domain (remove leading subdomain noise)
                parts = hostname.rstrip('.').split('.')
                if len(parts) >= 2:
                    return '.'.join(parts[-2:]) if len(parts) <= 3 else '.'.join(parts[-3:])
            return None
        except (socket.herror, socket.gaierror, OSError):
            return None

    with ThreadPoolExecutor(max_workers=_REVERSE_DNS_WORKERS) as pool:
        futures = {pool.submit(_lookup, ip): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                domains.append(result)

    return domains
