"""
DNS Zone Enumeration — Advanced DNS enumeration beyond basic record types.

Queries SRV records, performs NSEC walking, nameserver version fingerprinting,
DNS cache snooping, and zone consistency checks.
"""
import logging
import time

from ._base import create_result, add_finding, finalize_result, extract_hostname

logger = logging.getLogger(__name__)

# Common SRV service prefixes
SRV_PREFIXES_COMMON = [
    '_http._tcp', '_https._tcp', '_sip._tcp', '_sip._udp', '_ftp._tcp',
    '_smtp._tcp', '_imap._tcp', '_pop3._tcp', '_ldap._tcp', '_kerberos._tcp',
    '_caldav._tcp', '_carddav._tcp', '_xmpp-client._tcp', '_xmpp-server._tcp',
    '_jabber._tcp', '_turn._tcp', '_stun._tcp', '_minecraft._tcp',
    '_ntp._udp', '_rdp._tcp',
]

SRV_PREFIXES_EXTENDED = SRV_PREFIXES_COMMON + [
    '_vnc._tcp', '_ssh._tcp', '_telnet._tcp', '_h323cs._tcp', '_sips._tcp',
    '_submission._tcp', '_imaps._tcp', '_pop3s._tcp', '_ftps._tcp',
    '_mysqlx._tcp', '_postgresql._tcp', '_mongodb._tcp', '_redis._tcp',
    '_amqp._tcp', '_mqtt._tcp', '_coap._udp', '_etcd._tcp',
    '_k8s._tcp', '_consul._tcp', '_vault._tcp', '_prometheus._tcp',
    '_grafana._tcp', '_elasticsearch._tcp', '_kibana._tcp', '_logstash._tcp',
    '_jenkins._tcp', '_gitlab._tcp', '_docker._tcp', '_mattermost._tcp',
    '_matrix._tcp', '_webdav._tcp', '_svn._tcp', '_git._tcp',
]

# Public DNS resolvers for consistency checks
PUBLIC_RESOLVERS = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']

# Common internal hostnames for cache snooping
CACHE_SNOOP_NAMES = [
    'intranet', 'internal', 'vpn', 'mail', 'webmail', 'owa',
    'admin', 'portal', 'staging', 'dev', 'test', 'jira',
    'confluence', 'gitlab', 'jenkins', 'ci', 'cd', 'api',
    'db', 'database', 'redis', 'mongo', 'elastic', 'kibana',
]

# DNSBL services for reputation checks
DNSBL_SERVICES = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org',
    'dnsbl.sorbs.net',
]


def run_dns_zone_enum(target_url: str, depth: str = 'medium', **kwargs) -> dict:
    """
    Advanced DNS enumeration beyond basic record types.

    shallow : SRV records for 20 common services
    medium  : + NSEC walking attempt, NS version fingerprinting, cache snooping
    deep    : + All SRV prefixes (50+), zone consistency, DNSBL reputation
    """
    start = time.time()
    result = create_result('dns_zone_enum', target_url, depth)
    hostname = extract_hostname(target_url)

    if not hostname:
        result['errors'].append('Could not extract hostname')
        return finalize_result(result, start)

    try:
        import dns.resolver
        import dns.rdatatype
    except ImportError:
        result['errors'].append('dnspython not installed')
        return finalize_result(result, start)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    # 1. SRV record enumeration
    prefixes = SRV_PREFIXES_COMMON if depth == 'shallow' else SRV_PREFIXES_EXTENDED
    srv_findings = []
    for prefix in prefixes:
        srv_name = f'{prefix}.{hostname}'
        result['stats']['total_checks'] += 1
        try:
            answers = resolver.resolve(srv_name, 'SRV')
            for rdata in answers:
                srv_findings.append({
                    'service': prefix,
                    'target': str(rdata.target).rstrip('.'),
                    'port': rdata.port,
                    'priority': rdata.priority,
                    'weight': rdata.weight,
                })
                result['stats']['successful_checks'] += 1
        except Exception:
            result['stats']['failed_checks'] += 1

    if srv_findings:
        add_finding(result, {
            'type': 'srv_records',
            'severity': 'info',
            'title': f'SRV records found ({len(srv_findings)})',
            'details': srv_findings,
        })

    if depth in ('medium', 'deep'):
        # 2. Nameserver version fingerprinting (CHAOS TXT)
        try:
            ns_answers = resolver.resolve(hostname, 'NS')
            ns_servers = [str(r).rstrip('.') for r in ns_answers]
        except Exception:
            ns_servers = []

        for ns in ns_servers[:4]:
            result['stats']['total_checks'] += 1
            try:
                ns_resolver = dns.resolver.Resolver()
                ns_resolver.nameservers = [str(dns.resolver.resolve(ns, 'A')[0])]
                ns_resolver.timeout = 3
                ns_resolver.lifetime = 5
                version_answers = ns_resolver.resolve('version.bind', 'TXT',
                                                       rdclass=dns.rdataclass.CH)
                version = str(version_answers[0]).strip('"')
                add_finding(result, {
                    'type': 'ns_version',
                    'severity': 'low',
                    'title': f'NS version disclosed: {ns}',
                    'details': {'nameserver': ns, 'version': version},
                })
                result['stats']['successful_checks'] += 1
            except Exception:
                result['stats']['failed_checks'] += 1

        # 3. NSEC/NSEC3 walking attempt
        result['stats']['total_checks'] += 1
        try:
            nsec_answers = resolver.resolve(hostname, 'NSEC')
            nsec_records = [str(r) for r in nsec_answers]
            if nsec_records:
                add_finding(result, {
                    'type': 'nsec_records',
                    'severity': 'low',
                    'title': 'DNSSEC NSEC records allow zone walking',
                    'details': nsec_records[:10],
                })
                result['stats']['successful_checks'] += 1
        except Exception:
            result['stats']['failed_checks'] += 1

        # 4. DNS cache snooping
        cache_hits = []
        for name in CACHE_SNOOP_NAMES[:15]:
            fqdn = f'{name}.{hostname}'
            result['stats']['total_checks'] += 1
            try:
                answers = resolver.resolve(fqdn, 'A')
                ips = [str(r) for r in answers]
                cache_hits.append({'name': fqdn, 'ips': ips})
                result['stats']['successful_checks'] += 1
            except Exception:
                result['stats']['failed_checks'] += 1

        if cache_hits:
            add_finding(result, {
                'type': 'cache_snoop',
                'severity': 'info',
                'title': f'DNS cache snooping: {len(cache_hits)} internal names resolved',
                'details': cache_hits,
            })

    if depth == 'deep':
        # 5. Zone consistency across resolvers
        inconsistencies = []
        result['stats']['total_checks'] += 1
        try:
            results_per_resolver = {}
            for res_ip in PUBLIC_RESOLVERS:
                test_resolver = dns.resolver.Resolver()
                test_resolver.nameservers = [res_ip]
                test_resolver.timeout = 5
                test_resolver.lifetime = 8
                try:
                    answers = test_resolver.resolve(hostname, 'A')
                    results_per_resolver[res_ip] = sorted(str(r) for r in answers)
                except Exception:
                    results_per_resolver[res_ip] = []

            ip_sets = list(results_per_resolver.values())
            if ip_sets and not all(s == ip_sets[0] for s in ip_sets):
                inconsistencies.append({
                    'type': 'zone_inconsistency',
                    'resolvers': results_per_resolver,
                })
                result['stats']['successful_checks'] += 1
        except Exception:
            result['stats']['failed_checks'] += 1

        if inconsistencies:
            add_finding(result, {
                'type': 'zone_inconsistency',
                'severity': 'medium',
                'title': 'DNS zone inconsistency across resolvers',
                'details': inconsistencies,
            })

        # 6. DNSBL reputation lookups
        try:
            a_records = resolver.resolve(hostname, 'A')
            target_ip = str(a_records[0])
        except Exception:
            target_ip = None

        if target_ip:
            reversed_ip = '.'.join(reversed(target_ip.split('.')))
            for dnsbl in DNSBL_SERVICES:
                query = f'{reversed_ip}.{dnsbl}'
                result['stats']['total_checks'] += 1
                try:
                    resolver.resolve(query, 'A')
                    add_finding(result, {
                        'type': 'dnsbl_listed',
                        'severity': 'medium',
                        'title': f'IP listed in DNSBL: {dnsbl}',
                        'details': {'ip': target_ip, 'dnsbl': dnsbl},
                    })
                    result['stats']['successful_checks'] += 1
                except Exception:
                    result['stats']['failed_checks'] += 1

    return finalize_result(result, start)
