"""
Reverse DNS Sweep — Discover hostnames sharing IP space with the target.

Given IP addresses and CIDR ranges from ASN recon, performs reverse DNS
lookups to find co-hosted domains and related infrastructure. This reveals
the target's "neighbourhood" — other hosts on the same servers or network
segments.

Techniques:
    • PTR record lookup for individual IPs
    • Sweep small CIDRs (/24 and smaller)
    • HackerTarget reverse IP API for virtual host discovery
    • Concurrent execution with configurable workers

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import socket
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

# Max IPs to sweep (prevent accidentally scanning /16)
_MAX_SWEEP_IPS = 256

# Max concurrent reverse lookups
_MAX_WORKERS = 30

# DNS resolution timeout
_RESOLVE_TIMEOUT = 3


def _reverse_dns(ip: str) -> str | None:
    """Perform a PTR (reverse DNS) lookup for an IP."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_RESOLVE_TIMEOUT)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.lower()
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _cidr_to_ips(cidr: str, max_ips: int = _MAX_SWEEP_IPS) -> list[str]:
    """Expand a CIDR notation to individual IP addresses.

    Only expands /24 or smaller to avoid massive sweeps.
    """
    try:
        from netaddr import IPNetwork
        network = IPNetwork(cidr)
        # Only sweep /24 and smaller
        if network.prefixlen < 24:
            return []
        ips = [str(ip) for ip in network]
        return ips[:max_ips]
    except ImportError:
        # Fallback: basic /24 expansion for x.x.x.0/24 format
        parts = cidr.split('/')
        if len(parts) != 2:
            return []
        prefix_len = int(parts[1])
        if prefix_len < 24:
            return []
        base_ip = parts[0]
        octets = base_ip.split('.')
        if len(octets) != 4:
            return []
        base = '.'.join(octets[:3])
        return [f'{base}.{i}' for i in range(1, min(255, max_ips + 1))]
    except Exception as e:
        logger.debug('CIDR expansion failed for %s: %s', cidr, e)
        return []


def _hackertarget_reverse_ip(ip: str) -> list[str]:
    """Query HackerTarget reverse IP lookup API."""
    domains = []
    try:
        url = f'https://api.hackertarget.com/reverseiplookup/?q={quote(ip)}'
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and 'error' not in resp.text.lower():
            for line in resp.text.strip().splitlines():
                host = line.strip().lower()
                if host and '.' in host:
                    domains.append(host)
    except Exception as e:
        logger.debug('HackerTarget reverse IP failed for %s: %s', ip, e)
    return domains


def run_reverse_dns(
    target_url: str,
    ip_addresses: list[str] | None = None,
    cidrs: list[str] | None = None,
) -> dict:
    """
    Perform reverse DNS sweep on target's IP space.

    Args:
        target_url: The target URL.
        ip_addresses: Known IP addresses from DNS recon.
        cidrs: CIDR ranges from ASN recon.

    Returns standardised dict plus legacy keys:
        ptr_records, virtual_hosts, related_domains, total_discovered
    """
    start = time.time()
    result = create_result('reverse_dns', target_url, 'deep')
    hostname = extract_hostname(target_url)
    target_domain = extract_root_domain(hostname)

    ip_addresses = ip_addresses or []
    cidrs = cidrs or []

    # Expand CIDRs and merge with known IPs
    all_ips = set(ip_addresses)
    for cidr in cidrs[:5]:  # Limit CIDR expansion to 5 ranges
        expanded = _cidr_to_ips(cidr)
        all_ips.update(expanded)

    if not all_ips:
        result['errors'].append('No IP addresses to sweep')
        return finalize_result(result, start)

    all_ips = list(all_ips)[:_MAX_SWEEP_IPS]
    result['stats']['total_checks'] = len(all_ips)

    # Concurrent reverse DNS lookups
    ptr_records: dict[str, str] = {}  # ip → hostname
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(_reverse_dns, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                hostname_result = future.result()
                if hostname_result:
                    ptr_records[ip] = hostname_result
                    result['stats']['successful_checks'] += 1
                else:
                    result['stats']['failed_checks'] += 1
            except Exception:
                result['stats']['failed_checks'] += 1

    # HackerTarget reverse IP for the primary IPs (max 3)
    virtual_hosts: dict[str, list[str]] = {}
    for ip in ip_addresses[:3]:
        vhosts = _hackertarget_reverse_ip(ip)
        if vhosts:
            virtual_hosts[ip] = vhosts

    # Categorize results
    related_domains = set()
    same_org_hosts = set()
    for ip, host in ptr_records.items():
        if target_domain and host.endswith(f'.{target_domain}'):
            same_org_hosts.add(host)
        else:
            related_domains.add(host)

    for ip, hosts in virtual_hosts.items():
        for host in hosts:
            domain = extract_root_domain(host)
            if domain == target_domain:
                same_org_hosts.add(host)
            else:
                related_domains.add(host)

    # Findings
    if ptr_records:
        add_finding(result, {
            'type': 'ptr_records',
            'total': len(ptr_records),
            'records': dict(list(ptr_records.items())[:100]),
        })

    if same_org_hosts:
        add_finding(result, {
            'type': 'same_org_hosts',
            'total': len(same_org_hosts),
            'hosts': sorted(same_org_hosts)[:100],
        })

    if related_domains:
        add_finding(result, {
            'type': 'neighbouring_hosts',
            'total': len(related_domains),
            'hosts': sorted(related_domains)[:100],
        })

    if virtual_hosts:
        add_finding(result, {
            'type': 'virtual_hosts',
            'total_ips_checked': len(virtual_hosts),
            'hosts': {ip: hosts[:50] for ip, hosts in virtual_hosts.items()},
        })

    # Legacy keys
    result['ptr_records'] = ptr_records
    result['virtual_hosts'] = virtual_hosts
    result['same_org_hosts'] = sorted(same_org_hosts)
    result['related_domains'] = sorted(related_domains)
    result['total_discovered'] = len(ptr_records) + sum(len(v) for v in virtual_hosts.values())

    logger.info(
        'Reverse DNS: %d PTR records, %d same-org hosts, %d neighbours from %d IPs',
        len(ptr_records), len(same_org_hosts), len(related_domains), len(all_ips),
    )

    return finalize_result(result, start)
