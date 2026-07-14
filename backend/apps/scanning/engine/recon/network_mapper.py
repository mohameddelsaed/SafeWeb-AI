"""
Network Mapper Module — Map network topology from gathered intelligence.

Aggregates DNS, subdomain, and port scan data to build a network map
showing relationships between hosts, IPs, and services.

Pure aggregation — no network requests needed.

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import time
from collections import defaultdict

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# Known CDN IP ranges (CIDR-style prefixes for lightweight matching)
_CDN_INDICATORS: list[tuple[str, str]] = [
    ('104.16.', 'Cloudflare'),
    ('104.17.', 'Cloudflare'),
    ('104.18.', 'Cloudflare'),
    ('104.19.', 'Cloudflare'),
    ('104.20.', 'Cloudflare'),
    ('104.21.', 'Cloudflare'),
    ('104.22.', 'Cloudflare'),
    ('172.67.', 'Cloudflare'),
    ('13.32.', 'CloudFront'),
    ('13.33.', 'CloudFront'),
    ('13.35.', 'CloudFront'),
    ('18.64.', 'CloudFront'),
    ('99.84.', 'CloudFront'),
    ('143.204.', 'CloudFront'),
    ('151.101.', 'Fastly'),
    ('199.232.', 'Fastly'),
    ('23.185.', 'Fastly'),
    ('205.251.', 'AWS/Route53'),
    ('76.76.21.', 'Vercel'),
    ('216.239.', 'Google'),
    ('142.250.', 'Google'),
    ('20.', 'Azure'),
    ('13.', 'AWS'),
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _identify_cdn(ip: str) -> str | None:
    """Return CDN name if *ip* matches a known CDN prefix, else *None*."""
    for prefix, cdn_name in _CDN_INDICATORS:
        if ip.startswith(prefix):
            return cdn_name
    return None


def _extract_ips_from_dns(dns_results: dict) -> dict[str, list[str]]:
    """Return ``{hostname: [ips]}`` from DNS recon results."""
    mapping: dict[str, list[str]] = defaultdict(list)
    if not dns_results:
        return mapping

    hostname = dns_results.get('hostname', '')
    for ip in dns_results.get('ip_addresses', []):
        if isinstance(ip, str) and ip:
            mapping[hostname].append(ip)

    # Subdomain entries
    for sub in dns_results.get('subdomains', []):
        if isinstance(sub, dict):
            # dns_recon stores as {'subdomain': fqdn, 'ip': ip}
            # subdomain_enum stores as {'name': fqdn, 'ip': ip} — handle both
            name = sub.get('subdomain', sub.get('name', ''))
            ip = sub.get('ip', '')
            if name and ip:
                mapping[name].append(ip)
        elif isinstance(sub, str):
            mapping[sub]  # ensure key exists

    return mapping


def _extract_ips_from_subdomains(subdomain_results: dict) -> dict[str, list[str]]:
    """Return ``{hostname: [ips]}`` from subdomain enum/brute results."""
    mapping: dict[str, list[str]] = defaultdict(list)
    if not subdomain_results:
        return mapping

    for key in ('subdomains', 'new_subdomains'):
        for entry in subdomain_results.get(key, []):
            if isinstance(entry, dict):
                name = entry.get('name', '')
                ip = entry.get('ip', '')
                if name and ip:
                    mapping[name].append(ip)
    return mapping


def _extract_ips_from_certs(cert_results: dict) -> dict[str, list[str]]:
    """Return ``{hostname: []}`` from certificate analysis (no IPs, but hostnames)."""
    mapping: dict[str, list[str]] = defaultdict(list)
    if not cert_results:
        return mapping

    for name in cert_results.get('sans', []):
        if isinstance(name, str) and name:
            clean = name.lstrip('*.')
            mapping[clean]  # record hostname; IP unknown
    return mapping


def _extract_services_from_ports(port_results: dict) -> dict[str, list[dict]]:
    """Return ``{ip_or_host: [{port, service, state}]}`` from port scan results."""
    services: dict[str, list[dict]] = defaultdict(list)
    if not port_results:
        return services

    host = port_results.get('hostname', port_results.get('target', ''))
    for port_entry in port_results.get('open_ports', port_results.get('ports', [])):
        if isinstance(port_entry, dict):
            services[host].append({
                'port': port_entry.get('port'),
                'service': port_entry.get('service', 'unknown'),
                'state': port_entry.get('state', 'open'),
            })
        elif isinstance(port_entry, int):
            services[host].append({
                'port': port_entry,
                'service': 'unknown',
                'state': 'open',
            })
    return services


def _merge_mappings(*mappings: dict[str, list]) -> dict[str, list]:
    """Merge multiple ``{key: [values]}`` dicts, deduplicating values."""
    merged: dict[str, list] = defaultdict(list)
    for m in mappings:
        for key, values in m.items():
            for v in values:
                if v not in merged[key]:
                    merged[key].append(v)
    return dict(merged)


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_network_mapper(
    target_url: str,
    dns_results: dict | None = None,
    subdomain_results: dict | None = None,
    port_results: dict | None = None,
    cert_results: dict | None = None,
) -> dict:
    """Build a network topology from aggregated recon data.

    Args:
        target_url:        Target URL.
        dns_results:       Dict from ``run_dns_recon`` (optional).
        subdomain_results: Dict from subdomain enum/brute (optional).
        port_results:      Dict from ``run_port_scanner`` (optional).
        cert_results:      Dict from ``run_cert_analysis`` (optional).

    Returns:
        Standardised result dict with legacy keys:
        ``hosts``, ``ip_map``, ``shared_ips``, ``cdn_ips``,
        ``topology``, ``total_hosts``, ``issues``.
    """
    start = time.time()
    result = create_result('network_mapper', target_url)

    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    # Legacy top-level keys
    result['hosts'] = []
    result['ip_map'] = {}
    result['shared_ips'] = []
    result['cdn_ips'] = []
    result['topology'] = {}
    result['total_hosts'] = 0

    if not root_domain:
        result['errors'].append('Could not extract root domain from target URL')
        return finalize_result(result, start)

    logger.info('Starting network mapping for %s', root_domain)
    checks = 0

    # 1. Aggregate host → IP mappings from all sources
    checks += 1
    try:
        dns_map = _extract_ips_from_dns(dns_results)
        sub_map = _extract_ips_from_subdomains(subdomain_results)
        cert_map = _extract_ips_from_certs(cert_results)
        host_ip_map = _merge_mappings(dns_map, sub_map, cert_map)
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        host_ip_map = {}
        result['errors'].append(f'IP aggregation error: {exc}')
        result['stats']['failed_checks'] += 1

    # 2. Extract service information from port scan
    checks += 1
    try:
        service_map = _extract_services_from_ports(port_results)
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        service_map = {}
        result['errors'].append(f'Service extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 3. Build reverse IP → hostnames map
    checks += 1
    try:
        ip_to_hosts: dict[str, list[str]] = defaultdict(list)
        for host, ips in host_ip_map.items():
            for ip in ips:
                if host not in ip_to_hosts[ip]:
                    ip_to_hosts[ip].append(host)
        result['ip_map'] = dict(ip_to_hosts)
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'Reverse map error: {exc}')
        result['stats']['failed_checks'] += 1

    # 4. Identify CDN vs origin IPs
    checks += 1
    cdn_ips: list[dict] = []
    origin_ips: list[str] = []
    try:
        all_ips = set()
        for ips in host_ip_map.values():
            all_ips.update(ips)

        for ip in sorted(all_ips):
            cdn = _identify_cdn(ip)
            if cdn:
                cdn_ips.append({'ip': ip, 'provider': cdn})
            else:
                origin_ips.append(ip)

        result['cdn_ips'] = cdn_ips
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'CDN identification error: {exc}')
        result['stats']['failed_checks'] += 1

    # 5. Detect shared hosting (multiple hostnames on same IP)
    checks += 1
    shared: list[dict] = []
    try:
        for ip, hosts in ip_to_hosts.items():
            if len(hosts) > 1:
                shared.append({'ip': ip, 'hostnames': hosts, 'count': len(hosts)})
        result['shared_ips'] = shared
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'Shared hosting detection error: {exc}')
        result['stats']['failed_checks'] += 1

    # 6. Build host entries and full topology
    checks += 1
    hosts_list: list[dict] = []
    try:
        for host in sorted(host_ip_map.keys()):
            ips = host_ip_map[host]
            services = service_map.get(host, [])
            hosts_list.append({
                'hostname': host,
                'ips': ips,
                'services': services,
            })
        result['hosts'] = hosts_list
        result['total_hosts'] = len(hosts_list)

        # Topology summary
        result['topology'] = {
            'total_hosts': len(hosts_list),
            'total_unique_ips': len(set(ip for ips in host_ip_map.values() for ip in ips)),
            'cdn_ips_count': len(cdn_ips),
            'origin_ips_count': len(origin_ips),
            'shared_hosting_groups': len(shared),
            'services_discovered': sum(len(s) for s in service_map.values()),
        }
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'Topology build error: {exc}')
        result['stats']['failed_checks'] += 1

    result['stats']['total_checks'] = checks

    # ── Findings ───────────────────────────────────────────────────────
    for host_entry in hosts_list:
        add_finding(result, {
            'type': 'host',
            'hostname': host_entry['hostname'],
            'ips': host_entry['ips'],
            'services': host_entry['services'],
        })

    for cdn_entry in cdn_ips:
        add_finding(result, {
            'type': 'cdn_ip',
            'ip': cdn_entry['ip'],
            'provider': cdn_entry['provider'],
        })

    for shared_entry in shared:
        add_finding(result, {
            'type': 'shared_hosting',
            'ip': shared_entry['ip'],
            'hostnames': shared_entry['hostnames'],
        })

    # ── Security observations ──────────────────────────────────────────
    if shared:
        result['issues'].append(
            f'{len(shared)} IP(s) host multiple domains — shared hosting '
            'increases lateral movement risk'
        )

    if cdn_ips and origin_ips:
        result['issues'].append(
            'Origin IP(s) detected alongside CDN — CDN bypass may be possible: '
            + ', '.join(origin_ips[:5])
        )
    elif not cdn_ips and hosts_list:
        result['issues'].append('No CDN detected — target may lack DDoS protection')

    if result['topology'].get('total_hosts', 0) > 20:
        result['issues'].append(
            f'Large attack surface: {result["topology"]["total_hosts"]} hosts discovered'
        )

    logger.info(
        'Network mapping complete for %s: %d hosts, %d IPs, %d CDN IPs, %d shared groups',
        root_domain,
        len(hosts_list),
        result['topology'].get('total_unique_ips', 0),
        len(cdn_ips),
        len(shared),
    )
    return finalize_result(result, start)
