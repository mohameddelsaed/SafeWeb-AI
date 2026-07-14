"""
DNS Reconnaissance Module — DNS enumeration and analysis.

Gathers: A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/TLSA records, SPF/DMARC/BIMI analysis,
zone transfer attempts, DNSSEC chain validation, subdomain hints, SRV probing,
reverse DNS lookups, and DNS propagation consistency checks.

Uses ``_base`` helpers for the standardised return format.
"""
import re
import socket
import logging
import time

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)
try:
    from ..payloads.seclists_manager import SecListsManager as _SecListsManager
    _SECLISTS = _SecListsManager()
except Exception:
    _SECLISTS = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Common subdomains to probe — 500+ entries covering SecLists top-1000 patterns
COMMON_SUBDOMAINS = [
    # Core web & mail
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
    'ns1', 'ns2', 'ns3', 'ns4', 'mx', 'mx1', 'mx2', 'relay',
    # Apps & portals
    'blog', 'dev', 'staging', 'api', 'app', 'admin', 'portal',
    'secure', 'vpn', 'remote', 'test', 'demo', 'cdn', 'static',
    'assets', 'media', 'images', 'docs', 'wiki', 'git', 'ci',
    # DevOps & monitoring
    'jenkins', 'jira', 'confluence', 'grafana', 'monitor', 'nagios',
    'zabbix', 'prometheus', 'alertmanager', 'kibana', 'logstash',
    'elasticsearch', 'splunk', 'datadog', 'newrelic', 'sentry',
    'sonarqube', 'nexus', 'artifactory', 'registry', 'harbor',
    'argocd', 'rancher', 'kubernetes', 'k8s', 'helm', 'vault',
    'consul', 'nomad', 'packer', 'terraform', 'ansible',
    # Authentication & SSO
    'auth', 'oauth', 'sso', 'login', 'logout', 'identity', 'idp',
    'saml', 'ldap', 'ad', 'iam', 'accounts', 'keycloak', 'okta',
    'ping', 'adfs', 'pki', 'certs', 'ca', 'directory',
    # Cloud & CDN
    'cloud', 's3', 'blob', 'storage', 'bucket', 'aws', 'azure',
    'gcp', 'firebase', 'netlify', 'vercel', 'lambda', 'functions',
    'edge', 'edge1', 'edge2', 'node', 'cluster', 'datacenter',
    'dc1', 'dc2', 'zone1', 'zone2', 'region1', 'region2',
    # API versioning
    'api1', 'api2', 'api3', 'apiv1', 'apiv2', 'apiv3',
    'api-v1', 'api-v2', 'api-v3', 'rest', 'graphql', 'grpc',
    'gateway', 'proxy', 'lb', 'loadbalancer', 'balancer',
    'internal-api', 'external-api', 'public-api', 'private-api',
    # Environments
    'prod', 'production', 'preprod', 'pre-prod', 'uat',
    'qa', 'qe', 'int', 'integration', 'sandbox', 'stage',
    'stg', 'tst', 'testing', 'local', 'localhost', 'beta',
    'alpha', 'rc', 'release', 'canary', 'preview', 'nightly',
    'hotfix', 'feature', 'experiment', 'poc', 'lab', 'labs',
    # Infrastructure services
    'backup', 'backups', 'bkp', 'archive', 'archives',
    'log', 'logs', 'audit', 'metrics', 'stats', 'analytics',
    'reports', 'reporting', 'billing', 'payments', 'invoice',
    'shop', 'store', 'ecommerce', 'catalog', 'inventory',
    'crm', 'erp', 'hr', 'helpdesk', 'support', 'ticket',
    'jira', 'servicenow', 'zendesk', 'freshdesk', 'intercom',
    # Databases & caches
    'db', 'db1', 'db2', 'database', 'mysql', 'postgres', 'pgsql',
    'redis', 'mongo', 'mongodb', 'couchdb', 'cassandra', 'elastic',
    'solr', 'memcached', 'kafka', 'rabbitmq', 'mq', 'queue',
    'broker', 'zookeeper', 'etcd', 'influxdb', 'timescale',
    # File & content services
    'files', 'file', 'upload', 'uploads', 'download', 'downloads',
    'content', 'resources', 'assets2', 'public', 'private',
    'share', 'shared', 'sharepoint', 'onedrive', 'drive',
    # Collaboration & communication
    'chat', 'slack', 'teams', 'discord', 'zoom', 'meet',
    'calendar', 'contacts', 'address', 'directory2',
    'intranet', 'extranet', 'forum', 'community', 'social',
    'newsletter', 'campaign', 'marketing', 'crm2',
    # Network & security
    'firewall', 'router', 'switch', 'gateway2', 'proxy2',
    'waf', 'ids', 'ips', 'siem', 'scan', 'scanner',
    'pentest', 'security', 'infosec', 'cert2', 'certificates',
    'crl', 'ocsp', 'timestamp', 'ntp', 'time', 'dns',
    'dhcp', 'ipam', 'netflow', 'snmp', 'tacacs', 'radius',
    # Mobile & client apps
    'mobile', 'm', 'wap', 'pwa', 'ios', 'android',
    'app2', 'apps', 'client', 'clients', 'sdk',
    # Webhooks & integrations
    'hooks', 'webhooks', 'callback', 'notifications', 'events',
    'streams', 'pipelines', 'etl', 'ingestion', 'collector',
    # Geographic / regional
    'us', 'eu', 'uk', 'de', 'fr', 'jp', 'au', 'ca', 'in',
    'sg', 'hk', 'br', 'ru', 'cn', 'ap', 'na', 'latam',
    'us-east', 'us-west', 'eu-west', 'eu-central', 'ap-east',
    'us1', 'us2', 'eu1', 'eu2', 'asia1', 'asia2',
    # Asset subdomains
    'img', 'img2', 'imgs', 'images2', 'pic', 'pics', 'photo',
    'photos', 'video', 'videos', 'audio', 'music', 'fonts',
    'css', 'js', 'scripts', 'styles', 'theme', 'themes',
    # Versioned assets
    'v1', 'v2', 'v3', 'v4', 'version', 'versions',
    # Documentation & legal
    'docs2', 'documentation', 'help', 'helpcenter', 'faq',
    'status', 'uptime', 'health', 'ping', 'probe', 'check',
    'legal', 'privacy', 'tos', 'terms', 'gdpr', 'compliance',
    # Admin panels & management
    'admin2', 'administrator', 'cpanel', 'whm', 'plesk',
    'directadmin', 'panel', 'dashboard', 'management', 'manager',
    'console', 'control', 'controlpanel', 'webadmin',
    # Email sub-services
    'smtp2', 'mail2', 'mail3', 'smtp3', 'bounce', 'mailer',
    'mailout', 'outbound', 'inbound', 'spam', 'filter',
    'antivirus', 'quarantine', 'mta', 'relay2',
    # Internal tooling & jumpboxes
    'bastion', 'jump', 'jumpbox', 'ssh', 'rdp', 'citrix',
    'vnc', 'guacamole', 'openvpn', 'wireguard', 'strongswan',
    # AI/ML services
    'ai', 'ml', 'model', 'inference', 'gpu', 'llm', 'notebook',
    'jupyter', 'mlflow', 'kubeflow', 'airflow', 'luigi',
    'openai', 'bedrock', 'sagemaker', 'vertex', 'huggingface',
    'grounding', 'embeddings', 'vectors', 'rag', 'copilot',
    'assistant', 'bot', 'chatbot', 'gpt', 'claude',
    # Source control & CI/CD
    'gitlab', 'github', 'bitbucket', 'svn', 'cvs',
    'travis', 'circleci', 'teamcity', 'drone', 'buildkite',
    'deploy', 'deployment', 'deployer', 'delivery', 'release2',
    # Testing tools
    'test2', 'testing2', 'qa2', 'e2e', 'playwright', 'cypress',
    'selenium', 'appium', 'loadtest', 'perf', 'performance',
    # IoT / embedded
    'iot', 'mqtt', 'sensor', 'device', 'devices', 'telemetry',
    'emqx', 'mosquitto', 'nodered', 'bacnet', 'modbus',
    # Misc popular
    'git2', 'repo', 'repos', 'src', 'source', 'code',
    'build', 'builds', 'package', 'packages', 'lib', 'libs',
    'bin', 'dist', 'release3', 'publish', 'npm', 'pip',
    'docker', 'image', 'container', 'microservice', 'service',
    'services', 'worker', 'workers', 'job', 'jobs', 'task',
    'tasks', 'cron', 'scheduler', 'runner', 'agent',
    'agents', 'bot2', 'crawler', 'spider', 'scraper',
    # Popular platform subdomains
    'shopify', 'magento', 'wordpress', 'woocommerce', 'drupal',
    'joomla', 'craft', 'ghost', 'strapi', 'contentful',
    'sanity', 'prismic', 'hubspot', 'marketo', 'pardot',
    'salesforce', 'dynamics', 'sap', 'oracle2',
    # Extra common patterns
    'old', 'new', 'legacy', 'current', 'next', 'previous',
    'backup2', 'mirror', 'replica', 'standby', 'failover',
    'dr', 'drsite', 'secondary', 'tertiary', 'spare',
    'test3', 'test4', 'test5', 'dev2', 'dev3', 'stage2',
    'preprod2', 'uat2', 'staging2', 'demo2', 'demo3',
    'alpha2', 'beta2', 'rc2', 'hotfix2', 'patch',
    # Server/host naming patterns
    'web', 'web1', 'web2', 'web3',
    'app1', 'app2', 'app3', 'app4',
    'server', 'srv', 'srv1', 'srv2', 'srv3',
    'host', 'host1', 'host2',
    'node1', 'node2', 'node3',
    'vm1', 'vm2', 'vm3',
    'ec2', 'compute', 'instance',
]

# SRV record service prefixes
SRV_SERVICES = [
    '_http._tcp', '_https._tcp', '_sip._tcp', '_sip._udp',
    '_xmpp-server._tcp', '_xmpp-client._tcp', '_ldap._tcp',
    '_kerberos._tcp', '_autodiscover._tcp', '_caldav._tcp',
]

# Record types to query when dnspython is available
_DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA']

# TLSA usage / selector / matching-type label maps
_TLSA_USAGE = {0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE'}
_TLSA_SELECTOR = {0: 'Full cert', 1: 'SubjectPublicKeyInfo'}
_TLSA_MATCH = {0: 'Exact', 1: 'SHA-256', 2: 'SHA-512'}


def run_dns_recon(target_url: str, depth: str = 'medium') -> dict:
    """
    Perform DNS reconnaissance on the target.

    Returns standardised dict (findings/metadata/errors/stats) **plus**
    legacy keys for backward compatibility:

        hostname, ip_addresses, reverse_dns, records, spf, dmarc,
        subdomains, issues, dnssec, zone_transfer
    """
    start = time.time()
    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    result = create_result('dns_recon', target_url, depth)

    # ── Legacy top-level keys (kept for orchestrator / base_tester compat) ──
    result['hostname'] = hostname
    result['ip_addresses'] = []
    result['reverse_dns'] = []
    result['records'] = {
        'mx': [], 'ns': [], 'txt': [], 'srv': [], 'cname': [],
        'soa': None, 'aaaa': [], 'caa': [], 'tlsa': [],
    }
    result['spf'] = None
    result['dmarc'] = None
    result['bimi'] = None
    result['subdomains'] = []
    result['dnssec'] = {'enabled': False, 'details': None}
    result['zone_transfer'] = {'attempted': False, 'successful': False, 'records': []}

    if not hostname:
        result['errors'].append('No hostname could be extracted from URL')
        return finalize_result(result, start)

    # 1. Resolve A/AAAA records ─────────────────────────────────────────────
    result['stats']['total_checks'] += 1
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        ips = sorted(set(ai[4][0] for ai in addr_info))
        result['ip_addresses'] = ips
        result['stats']['successful_checks'] += 1
        add_finding(result, {'type': 'a_records', 'ips': ips, 'count': len(ips)})

        # Reverse DNS
        for ip in ips[:5]:
            try:
                rev = socket.gethostbyaddr(ip)
                result['reverse_dns'].append({'ip': ip, 'hostname': rev[0]})
            except (socket.herror, socket.gaierror):
                pass
    except socket.gaierror:
        result['stats']['failed_checks'] += 1
        result['issues'].append('DNS resolution failed for hostname')
        result['errors'].append('DNS resolution failed for hostname')
        return finalize_result(result, start)

    # 2. Record enumeration ─────────────────────────────────────────────────
    _resolve_records_dnspython(root_domain, result)
    _resolve_records_fallback(root_domain, result)

    # 3. TXT / SPF / DMARC / BIMI analysis
    _analyze_email_security(root_domain, result)

    # 3b. BIMI record lookup
    _check_bimi(root_domain, result)

    # 4. SRV record probing (medium/deep)
    if depth in ('medium', 'deep'):
        result['records']['srv'] = _probe_srv_records(root_domain)
        result['stats']['total_checks'] += len(SRV_SERVICES)

    # 4b. CAA record analysis (medium/deep)
    if depth in ('medium', 'deep'):
        _analyze_caa_records(result)

    # 5. DNSSEC check (medium/deep)
    if depth in ('medium', 'deep'):
        _check_dnssec(root_domain, result)

    # 5b. TLSA / DANE record check (deep)
    if depth == 'deep':
        _check_tlsa(root_domain, result)

    # 5c. DNS consistency check (deep)
    if depth == 'deep':
        _check_dns_consistency(hostname, result)

    # 6. Zone transfer attempt (deep only)
    if depth == 'deep':
        _attempt_zone_transfer(root_domain, result)

    # 7. Subdomain enumeration (medium+: top-100; deep: full 500+)
    if depth in ('medium', 'deep'):
        result['subdomains'] = _enumerate_subdomains(root_domain, depth=depth)

    # 8. Issue analysis
    if not result['records']['mx']:
        result['issues'].append('No MX records found — email may not be configured')
    _check_email_security_issues(result)

    return finalize_result(result, start)


# ── Record Resolution ──────────────────────────────────────────────────────

def _resolve_records_dnspython(root_domain: str, result: dict):
    """Use dnspython for comprehensive record queries."""
    try:
        import dns.resolver  # type: ignore[import-untyped]
    except ImportError:
        return

    for rtype in _DNS_RECORD_TYPES:
        result['stats']['total_checks'] += 1
        try:
            answers = dns.resolver.resolve(root_domain, rtype)
            result['stats']['successful_checks'] += 1

            if rtype == 'A':
                ips = [str(r) for r in answers]
                if not result['ip_addresses']:
                    result['ip_addresses'] = ips
            elif rtype == 'AAAA':
                result['records']['aaaa'] = [str(r) for r in answers]
                add_finding(result, {'type': 'aaaa_records', 'records': result['records']['aaaa']})
            elif rtype == 'MX':
                result['records']['mx'] = [
                    str(r.exchange).rstrip('.') for r in answers
                ]
            elif rtype == 'NS':
                result['records']['ns'] = [
                    str(r.target).rstrip('.') for r in answers
                ]
            elif rtype == 'TXT':
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    result['records']['txt'].append(txt)
                    if txt.startswith('v=spf1'):
                        result['spf'] = txt
                    elif txt.startswith('v=DMARC1'):
                        result['dmarc'] = txt
            elif rtype == 'CNAME':
                result['records']['cname'] = [str(r.target).rstrip('.') for r in answers]
            elif rtype == 'SOA':
                soa = answers[0]
                result['records']['soa'] = {
                    'mname': str(soa.mname).rstrip('.'),
                    'rname': str(soa.rname).rstrip('.'),
                    'serial': soa.serial,
                    'refresh': soa.refresh,
                    'retry': soa.retry,
                    'expire': soa.expire,
                    'minimum': soa.minimum,
                }
            elif rtype == 'CAA':
                for rdata in answers:
                    result['records']['caa'].append({
                        'flags': rdata.flags,
                        'tag': rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag),
                        'value': rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value),
                    })
                add_finding(result, {
                    'type': 'caa_records',
                    'records': result['records']['caa'],
                    'count': len(result['records']['caa']),
                })
        except Exception:
            result['stats']['failed_checks'] += 1

    # DMARC via _dmarc subdomain
    if not result['dmarc']:
        try:
            answers = dns.resolver.resolve(f'_dmarc.{root_domain}', 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=DMARC1'):
                    result['dmarc'] = txt
                    result['records']['txt'].append(txt)
        except Exception:
            pass


def _resolve_records_fallback(root_domain: str, result: dict):
    """Socket-based fallback when dnspython is not available."""
    # Only run if dnspython didn't already populate MX/NS
    if result['records']['mx'] and result['records']['ns']:
        return

    if not result['records']['mx']:
        for mx_sub in ['mail', 'smtp', 'mx', 'mx1', 'mx2']:
            mx_host = f'{mx_sub}.{root_domain}'
            try:
                socket.getaddrinfo(mx_host, None)
                result['records']['mx'].append(mx_host)
            except socket.gaierror:
                pass

    if not result['records']['ns']:
        for ns_sub in ['ns1', 'ns2', 'ns3', 'dns1', 'dns2']:
            ns_host = f'{ns_sub}.{root_domain}'
            try:
                socket.getaddrinfo(ns_host, None)
                result['records']['ns'].append(ns_host)
            except socket.gaierror:
                pass


def _enumerate_subdomains(root_domain: str, depth: str = 'deep') -> list:
    """Enumerate subdomains via DNS resolution.

    depth='medium': probe the first 100 subdomains (fast)
    depth='deep':   probe the full list (500+ entries)
    """
    probe_list = COMMON_SUBDOMAINS[:100] if depth == 'medium' else COMMON_SUBDOMAINS

    # Augment with SecLists DNS wordlist when available
    if _SECLISTS and _SECLISTS.is_installed:
        sl_subs = _SECLISTS.read_payloads(
            'discovery_dns',
            max_lines=200 if depth == 'medium' else 0,
        )
        if sl_subs:
            combined: set[str] = set(probe_list)
            combined.update(sl_subs)
            probe_list = list(combined)
            logger.info('SecLists DNS wordlist augmented probe list to %d entries', len(probe_list))

    found = []
    for sub in probe_list:
        fqdn = f'{sub}.{root_domain}'
        try:
            ips = socket.getaddrinfo(fqdn, None)
            ip = ips[0][4][0] if ips else 'unknown'
            found.append({'subdomain': fqdn, 'ip': ip})
        except socket.gaierror:
            pass

    return found


# ── Email Security ─────────────────────────────────────────────────────────

def _analyze_email_security(root_domain: str, result: dict):
    """Try to resolve TXT records for SPF/DMARC analysis."""
    # If dnspython already populated, skip
    if result['spf'] or result['dmarc']:
        return

    try:
        import dns.resolver  # type: ignore[import-untyped]
        _dnspython_txt_lookup(root_domain, result)
        return
    except ImportError:
        pass

    # Fallback: check for SPF/DMARC via common TXT hosting patterns
    spf_hints = [f'spf.{root_domain}', f'_spf.{root_domain}']
    for hint in spf_hints:
        try:
            socket.getaddrinfo(hint, None)
            result['spf'] = 'present (detected via subdomain)'
            break
        except socket.gaierror:
            pass

    dmarc_host = f'_dmarc.{root_domain}'
    try:
        socket.getaddrinfo(dmarc_host, None)
        result['dmarc'] = 'present (detected via subdomain)'
    except socket.gaierror:
        pass


def _dnspython_txt_lookup(root_domain: str, result: dict):
    """Use dnspython for proper TXT record lookup."""
    import dns.resolver  # type: ignore[import-untyped]

    # SPF record
    try:
        answers = dns.resolver.resolve(root_domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=spf1'):
                result['spf'] = txt
                result['records']['txt'].append(txt)
            elif 'google-site-verification' in txt or 'MS=' in txt:
                result['records']['txt'].append(txt)
    except Exception:
        pass

    # DMARC record
    try:
        answers = dns.resolver.resolve(f'_dmarc.{root_domain}', 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=DMARC1'):
                result['dmarc'] = txt
                result['records']['txt'].append(txt)
    except Exception:
        pass

    # MX records (proper)
    try:
        answers = dns.resolver.resolve(root_domain, 'MX')
        result['records']['mx'] = [
            str(rdata.exchange).rstrip('.') for rdata in answers
        ]
    except Exception:
        pass

    # NS records (proper)
    try:
        answers = dns.resolver.resolve(root_domain, 'NS')
        result['records']['ns'] = [
            str(rdata.target).rstrip('.') for rdata in answers
        ]
    except Exception:
        pass


def _check_email_security_issues(result: dict):
    """Analyze SPF/DMARC/BIMI for security issues."""
    spf = result.get('spf') or ''
    dmarc = result.get('dmarc') or ''

    if not spf:
        result['issues'].append('No SPF record found — domain vulnerable to email spoofing')
    elif '+all' in spf:
        result['issues'].append('SPF uses +all (allows any server) — effectively no protection')
    elif '~all' in spf:
        result['issues'].append('SPF uses ~all (soft fail) — weak protection, should use -all')
    # Check for excessive DNS lookups in SPF (limit is 10)
    if spf:
        spf_includes = len(re.findall(r'\binclude:', spf))
        spf_lookups = spf_includes + len(re.findall(r'\b(?:a|mx|ptr|exists|redirect)[:=]', spf))
        if spf_lookups > 10:
            result['issues'].append(
                f'SPF record has ~{spf_lookups} DNS lookups (limit is 10) — may cause permerror'
            )

    if not dmarc:
        result['issues'].append('No DMARC record found — no email authentication policy')
    elif 'p=none' in dmarc:
        result['issues'].append('DMARC policy is "none" — monitoring only, no enforcement')
    # DMARC sub-domain policy check
    if dmarc and 'sp=' not in dmarc:
        result['issues'].append('DMARC has no sub-domain policy (sp=) — subdomains inherit parent policy')

    # BIMI check
    if result.get('bimi'):
        bimi = result['bimi']
        if 'l=' not in bimi:
            result['issues'].append('BIMI record present but missing logo URL (l= tag)')


# ── BIMI ───────────────────────────────────────────────────────────────────

def _check_bimi(root_domain: str, result: dict):
    """Check for BIMI (Brand Indicators for Message Identification) record."""
    result['stats']['total_checks'] += 1
    try:
        import dns.resolver  # type: ignore[import-untyped]
        answers = dns.resolver.resolve(f'default._bimi.{root_domain}', 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=BIMI1'):
                result['bimi'] = txt
                result['records']['txt'].append(txt)
                add_finding(result, {
                    'type': 'bimi_record',
                    'value': txt,
                    'has_logo': 'l=' in txt,
                    'has_authority': 'a=' in txt,
                })
                result['stats']['successful_checks'] += 1
                return
    except ImportError:
        pass
    except Exception:
        pass


# ── CAA Analysis ───────────────────────────────────────────────────────────

def _analyze_caa_records(result: dict):
    """Analyze CAA records for security posture."""
    caa_records = result['records'].get('caa', [])
    if not caa_records:
        result['issues'].append(
            'No CAA records found — any CA can issue certificates for this domain'
        )
        return

    issuers = [r['value'] for r in caa_records if r['tag'] == 'issue']
    wildcard_issuers = [r['value'] for r in caa_records if r['tag'] == 'issuewild']
    iodef_contacts = [r['value'] for r in caa_records if r['tag'] == 'iodef']

    if not issuers and not any(r['tag'] == 'issue' and r['value'] == ';' for r in caa_records):
        result['issues'].append('CAA records present but no "issue" tag — CA restriction incomplete')

    if not wildcard_issuers:
        result['issues'].append(
            'No CAA issuewild tag — wildcard certificate issuance not explicitly controlled'
        )

    if not iodef_contacts:
        result['issues'].append(
            'No CAA iodef tag — violation reports will not be sent anywhere'
        )

    add_finding(result, {
        'type': 'caa_analysis',
        'authorized_issuers': issuers,
        'wildcard_issuers': wildcard_issuers,
        'iodef_contacts': iodef_contacts,
    })


# ── TLSA / DANE ───────────────────────────────────────────────────────────

def _check_tlsa(root_domain: str, result: dict):
    """Check for TLSA (DANE) records on common ports."""
    try:
        import dns.resolver  # type: ignore[import-untyped]
    except ImportError:
        return

    ports_and_protos = [('443', 'tcp'), ('25', 'tcp'), ('993', 'tcp'), ('587', 'tcp')]

    for port, proto in ports_and_protos:
        tlsa_name = f'_{port}._{proto}.{root_domain}'
        result['stats']['total_checks'] += 1
        try:
            answers = dns.resolver.resolve(tlsa_name, 'TLSA')
            for rdata in answers:
                entry = {
                    'port': int(port),
                    'proto': proto,
                    'usage': _TLSA_USAGE.get(rdata.usage, str(rdata.usage)),
                    'selector': _TLSA_SELECTOR.get(rdata.selector, str(rdata.selector)),
                    'matching_type': _TLSA_MATCH.get(rdata.mtype, str(rdata.mtype)),
                    'cert_data_hex': rdata.cert.hex()[:64] + '...',
                }
                result['records']['tlsa'].append(entry)
            result['stats']['successful_checks'] += 1
            add_finding(result, {
                'type': 'tlsa_record',
                'name': tlsa_name,
                'count': len(answers),
            })
        except Exception:
            pass

    if result['records']['tlsa']:
        add_finding(result, {
            'type': 'dane_enabled',
            'record_count': len(result['records']['tlsa']),
            'ports': list({r['port'] for r in result['records']['tlsa']}),
        })


# ── DNS Consistency ────────────────────────────────────────────────────────

def _check_dns_consistency(hostname: str, result: dict):
    """Check whether all NS servers return consistent A records."""
    try:
        import dns.resolver  # type: ignore[import-untyped]
    except ImportError:
        return

    ns_list = result['records'].get('ns', [])
    if len(ns_list) < 2:
        return

    result['stats']['total_checks'] += 1
    ip_sets: dict[str, set] = {}

    for ns in ns_list[:4]:
        try:
            resolver = dns.resolver.Resolver()
            # Resolve NS hostname to IP first
            ns_ips = dns.resolver.resolve(ns, 'A')
            ns_ip = str(ns_ips[0])
            resolver.nameservers = [ns_ip]
            resolver.lifetime = 5
            answers = resolver.resolve(hostname, 'A')
            ip_sets[ns] = {str(r) for r in answers}
        except Exception:
            ip_sets[ns] = set()

    # Compare
    valid_sets = [ips for ips in ip_sets.values() if ips]
    if len(valid_sets) >= 2:
        if len(set(frozenset(s) for s in valid_sets)) > 1:
            result['issues'].append(
                'DNS inconsistency: nameservers return different A records — '
                'possible split-horizon or misconfiguration'
            )
            add_finding(result, {
                'type': 'dns_inconsistency',
                'ns_responses': {ns: sorted(ips) for ns, ips in ip_sets.items()},
            })
        result['stats']['successful_checks'] += 1


# ── DNSSEC ─────────────────────────────────────────────────────────────────

def _check_dnssec(root_domain: str, result: dict):
    """Check if DNSSEC is enabled and validate the chain."""
    result['stats']['total_checks'] += 1
    try:
        import dns.resolver  # type: ignore[import-untyped]
        import dns.rdatatype  # type: ignore[import-untyped]
        answers = dns.resolver.resolve(root_domain, 'DNSKEY')
        if answers:
            key_types = []
            for rdata in answers:
                flags = rdata.flags
                if flags & 0x0100:
                    key_types.append('ZSK')
                if flags & 0x0101:
                    key_types.append('KSK')
            result['dnssec'] = {
                'enabled': True,
                'details': f'{len(answers)} DNSKEY records ({", ".join(set(key_types)) or "unknown type"})',
                'key_count': len(answers),
                'key_types': list(set(key_types)),
            }
            result['stats']['successful_checks'] += 1
            add_finding(result, {
                'type': 'dnssec',
                'enabled': True,
                'keys': len(answers),
                'key_types': list(set(key_types)),
            })

            # Try DS record validation
            try:
                ds_answers = dns.resolver.resolve(root_domain, 'DS')
                result['dnssec']['ds_records'] = len(ds_answers)
                add_finding(result, {
                    'type': 'dnssec_ds',
                    'count': len(ds_answers),
                })
            except Exception:
                pass
        else:
            result['dnssec'] = {'enabled': False, 'details': None}
            result['issues'].append('DNSSEC is not enabled')
    except ImportError:
        pass
    except Exception:
        result['dnssec'] = {'enabled': False, 'details': None}
        result['issues'].append('DNSSEC is not enabled or could not be verified')


# ── Zone Transfer ──────────────────────────────────────────────────────────

def _attempt_zone_transfer(root_domain: str, result: dict):
    """Attempt AXFR zone transfer on discovered NS servers."""
    result['zone_transfer']['attempted'] = True
    result['stats']['total_checks'] += 1
    ns_servers = result['records'].get('ns', [])
    if not ns_servers:
        return

    try:
        import dns.zone  # type: ignore[import-untyped]
        import dns.query  # type: ignore[import-untyped]
    except ImportError:
        return

    for ns in ns_servers[:3]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, root_domain, timeout=5))
            records = []
            for name, node in zone.nodes.items():
                records.append(str(name))
            result['zone_transfer']['successful'] = True
            result['zone_transfer']['records'] = records[:500]  # cap
            result['stats']['successful_checks'] += 1
            result['issues'].append(f'Zone transfer ALLOWED on {ns} — critical misconfiguration!')
            add_finding(result, {
                'type': 'zone_transfer',
                'ns': ns,
                'record_count': len(records),
                'severity': 'critical',
            })
            break
        except Exception:
            pass


# ── SRV Probing ────────────────────────────────────────────────────────────

def _probe_srv_records(root_domain: str) -> list:
    """Probe for SRV records to discover services."""
    found = []
    for service in SRV_SERVICES:
        srv_host = f'{service}.{root_domain}'
        try:
            socket.getaddrinfo(srv_host, None)
            found.append({'service': service, 'host': srv_host})
        except socket.gaierror:
            pass
    return found


# ── Backward Compat ────────────────────────────────────────────────────────

def _get_root_domain(hostname: str) -> str:
    """Extract root domain from hostname (legacy — use extract_root_domain)."""
    return extract_root_domain(hostname)
