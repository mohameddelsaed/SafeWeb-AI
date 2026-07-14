"""
ASN & CIDR Reconnaissance — Autonomous System Number and IP range discovery.

Maps the target's IP addresses to their owning organizations, ASNs,
and CIDR blocks. This reveals the full network footprint of the target,
enabling reverse DNS sweeps and identifying related infrastructure.

Data sources (all free, no API key required):
    • Team Cymru DNS-based ASN lookup
    • BGPView API
    • RDAP/ARIN whois
    • ip-api.com

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import socket
import time
from urllib.parse import quote

import requests

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
)

logger = logging.getLogger(__name__)


def _resolve_ip(hostname: str) -> str | None:
    """Resolve hostname to first IPv4 address."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if results:
            return results[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


def _query_team_cymru(ip: str) -> dict:
    """Perform Team Cymru DNS-based ASN lookup.

    Query: dig +short <reversed-ip>.origin.asn.cymru.com TXT
    Response format: "ASN | prefix | CC | RIR | date"
    """
    info = {}
    try:
        import dns.resolver
        reversed_ip = '.'.join(reversed(ip.split('.')))

        # ASN origin query
        answers = dns.resolver.resolve(f'{reversed_ip}.origin.asn.cymru.com', 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            parts = [p.strip() for p in txt.split('|')]
            if len(parts) >= 3:
                info['asn'] = parts[0]
                info['prefix'] = parts[1]
                info['country'] = parts[2]
                if len(parts) >= 4:
                    info['rir'] = parts[3]

        # ASN name query
        if info.get('asn'):
            asn_num = info['asn'].split()[0]  # Handle "12345 12346" format
            try:
                name_answers = dns.resolver.resolve(f'AS{asn_num}.asn.cymru.com', 'TXT')
                for rdata in name_answers:
                    txt = str(rdata).strip('"')
                    parts = [p.strip() for p in txt.split('|')]
                    if len(parts) >= 5:
                        info['org_name'] = parts[4]
            except Exception:
                pass

    except ImportError:
        logger.debug('dnspython not available for Team Cymru lookup')
    except Exception as e:
        logger.debug('Team Cymru lookup failed for %s: %s', ip, e)
    return info


def _query_bgpview(ip: str) -> dict:
    """Query BGPView API for ASN and prefix information."""
    info = {'prefixes': [], 'asns': []}
    try:
        url = f'https://api.bgpview.io/ip/{quote(ip)}'
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'SafeWeb-AI/2.0'})
        if resp.status_code == 200:
            data = resp.json().get('data', {})

            # IP info
            info['rir'] = data.get('rir_allocation', {}).get('rir_name', '')

            # Prefixes
            for prefix_data in data.get('prefixes', []):
                prefix = prefix_data.get('prefix', '')
                asn_info = prefix_data.get('asn', {})
                if prefix:
                    info['prefixes'].append({
                        'prefix': prefix,
                        'asn': asn_info.get('asn', ''),
                        'name': asn_info.get('name', ''),
                        'description': asn_info.get('description', ''),
                        'country': asn_info.get('country_code', ''),
                    })
                    if asn_info.get('asn'):
                        info['asns'].append({
                            'asn': asn_info['asn'],
                            'name': asn_info.get('name', ''),
                            'description': asn_info.get('description', ''),
                        })

    except Exception as e:
        logger.debug('BGPView query failed for %s: %s', ip, e)
    return info


def _query_bgpview_asn_prefixes(asn: int | str) -> list[dict]:
    """Get all announced prefixes for a given ASN."""
    prefixes = []
    try:
        asn_num = str(asn).replace('AS', '')
        url = f'https://api.bgpview.io/asn/{quote(asn_num)}/prefixes'
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'SafeWeb-AI/2.0'})
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            for p in data.get('ipv4_prefixes', []):
                prefixes.append({
                    'prefix': p.get('prefix', ''),
                    'name': p.get('name', ''),
                    'description': p.get('description', ''),
                    'country': p.get('country_code', ''),
                })
    except Exception as e:
        logger.debug('BGPView ASN prefixes query failed for %s: %s', asn, e)
    return prefixes


def _query_ipapi(ip: str) -> dict:
    """Query ip-api.com for geolocation and org info."""
    info = {}
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,isp,org,as,asname'
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                info = {
                    'org': data.get('org', ''),
                    'isp': data.get('isp', ''),
                    'as_string': data.get('as', ''),
                    'as_name': data.get('asname', ''),
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                }
    except Exception as e:
        logger.debug('ip-api.com query failed for %s: %s', ip, e)
    return info


# ── Main Entry Point ─────────────────────────────────────────────────────────

def run_asn_recon(target_url: str) -> dict:
    """
    Perform ASN/CIDR reconnaissance for the target.

    Returns standardised dict plus legacy keys:
        ip, asn, org, cidrs, prefixes, geolocation
    """
    start = time.time()
    result = create_result('asn_recon', target_url, 'deep')
    hostname = extract_hostname(target_url)

    if not hostname:
        result['errors'].append('Could not extract hostname from target URL')
        return finalize_result(result, start)

    # Resolve IP
    ip = _resolve_ip(hostname)
    if not ip:
        result['errors'].append(f'Could not resolve IP for {hostname}')
        return finalize_result(result, start)

    result['stats']['total_checks'] = 3  # Cymru + BGPView + ip-api

    # Team Cymru lookup
    cymru = _query_team_cymru(ip)
    if cymru:
        result['stats']['successful_checks'] += 1
    else:
        result['stats']['failed_checks'] += 1

    # BGPView lookup
    bgpview = _query_bgpview(ip)
    if bgpview.get('prefixes') or bgpview.get('asns'):
        result['stats']['successful_checks'] += 1
    else:
        result['stats']['failed_checks'] += 1

    # ip-api geolocation
    geo = _query_ipapi(ip)
    if geo:
        result['stats']['successful_checks'] += 1
    else:
        result['stats']['failed_checks'] += 1

    # Determine primary ASN
    primary_asn = cymru.get('asn', '').split()[0] if cymru.get('asn') else ''
    if not primary_asn and bgpview.get('asns'):
        primary_asn = str(bgpview['asns'][0].get('asn', ''))

    # Get all prefixes for the ASN (deep enumeration)
    all_prefixes = []
    if primary_asn:
        result['stats']['total_checks'] += 1
        asn_prefixes = _query_bgpview_asn_prefixes(primary_asn)
        if asn_prefixes:
            all_prefixes = asn_prefixes
            result['stats']['successful_checks'] += 1
        else:
            result['stats']['failed_checks'] += 1

    # Build CIDR list
    cidrs = []
    seen_cidrs = set()
    for p in all_prefixes:
        prefix = p.get('prefix', '')
        if prefix and prefix not in seen_cidrs:
            seen_cidrs.add(prefix)
            cidrs.append(prefix)

    # Also add the direct prefix from Cymru
    if cymru.get('prefix') and cymru['prefix'] not in seen_cidrs:
        cidrs.insert(0, cymru['prefix'])
        seen_cidrs.add(cymru['prefix'])

    org_name = (
        cymru.get('org_name', '')
        or geo.get('org', '')
        or (bgpview['asns'][0].get('description', '') if bgpview.get('asns') else '')
    )

    # Findings
    add_finding(result, {
        'type': 'asn_info',
        'ip': ip,
        'asn': primary_asn,
        'org': org_name,
        'country': cymru.get('country', '') or geo.get('country_code', ''),
        'rir': cymru.get('rir', '') or bgpview.get('rir', ''),
    })

    if cidrs:
        add_finding(result, {
            'type': 'cidr_ranges',
            'total': len(cidrs),
            'cidrs': cidrs[:50],  # Cap at 50 most relevant
        })

    if geo:
        add_finding(result, {
            'type': 'geolocation',
            **geo,
        })

    # Legacy keys
    result['ip'] = ip
    result['asn'] = primary_asn
    result['org'] = org_name
    result['cidrs'] = cidrs
    result['prefixes'] = all_prefixes[:50]
    result['geolocation'] = geo

    logger.info(
        'ASN recon: IP=%s, ASN=%s, org=%s, %d CIDRs for %s',
        ip, primary_asn, org_name, len(cidrs), hostname,
    )

    # ── External ASN scanner augmentation (asnmap) ──
    try:
        from apps.scanning.engine.tools.wrappers.asnmap_wrapper import AsnmapTool
        _am = AsnmapTool()
        if _am.is_available():
            _existing_cidrs = set(cidrs)
            for _tr in _am.run(hostname):
                for _cidr in _tr.metadata.get('cidrs', []):
                    if _cidr not in _existing_cidrs:
                        _existing_cidrs.add(_cidr)
                        cidrs.append(_cidr)
            result['cidrs'] = cidrs
    except Exception:
        pass

    return finalize_result(result, start)
