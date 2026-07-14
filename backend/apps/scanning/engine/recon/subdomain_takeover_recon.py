"""
Subdomain Takeover Recon — Detect dangling DNS records and takeover-vulnerable subdomains.

Checks 20+ service fingerprints, CNAME NXDOMAIN detection,
NS delegation orphans, and MX dangling records.
"""
import logging
import re
import time

from ._base import create_result, add_finding, finalize_result, extract_hostname

logger = logging.getLogger(__name__)

# Service takeover fingerprints: (service, cname_patterns, body_fingerprints, severity)
TAKEOVER_FINGERPRINTS = [
    ('GitHub Pages', [r'github\.io$'], ["There isn't a GitHub Pages site here"], 'critical'),
    ('Heroku', [r'\.herokuapp\.com$', r'\.herokucdn\.com$'],
     ['No such app', "there is no app configured at that hostname", 'herokucdn.com/error-pages'], 'critical'),
    ('AWS S3', [r'\.s3\.amazonaws\.com$', r'\.s3-website.*\.amazonaws\.com$'],
     ['NoSuchBucket', 'The specified bucket does not exist'], 'critical'),
    ('AWS CloudFront', [r'\.cloudfront\.net$'],
     ["Bad request", "ERROR: The request could not be satisfied"], 'high'),
    ('Azure App Service', [r'\.azurewebsites\.net$', r'\.cloudapp\.azure\.com$'],
     ['is not found in the Azure cloud', 'Error 404 - Web app not found'], 'critical'),
    ('Azure Traffic Manager', [r'\.trafficmanager\.net$'],
     ['is not found in the Azure cloud'], 'critical'),
    ('Shopify', [r'\.myshopify\.com$'],
     ['Sorry, this shop is currently unavailable'], 'critical'),
    ('Fastly', [r'\.fastly\.net$', r'\.fastlylb\.net$'],
     ['Fastly error: unknown domain'], 'critical'),
    ('Pantheon', [r'\.pantheonsite\.io$'],
     ['The gods are wise, but do not know of the site which you seek'], 'critical'),
    ('Netlify', [r'\.netlify\.app$', r'\.netlify\.com$'],
     ['Not Found - Request ID'], 'critical'),
    ('Zendesk', [r'\.zendesk\.com$'],
     ['Help Center Closed', 'Oops, this help center no longer exists'], 'critical'),
    ('Ghost', [r'\.ghost\.io$'],
     ['Failed to resolve DNS', 'The thing you were looking for is no longer here'], 'critical'),
    ('Surge.sh', [r'\.surge\.sh$'],
     ['project not found'], 'critical'),
    ('ReadTheDocs', [r'\.readthedocs\.io$'],
     ['unknown to Read the Docs'], 'high'),
    ('Cargo', [r'\.cargocollective\.com$'],
     ["If you're moving your domain away from Cargo"], 'critical'),
    ('UserVoice', [r'\.uservoice\.com$'],
     ['This UserVoice subdomain is currently available'], 'critical'),
    ('Unbounce', [r'\.unbounce\.com$', r'unbouncepages\.com$'],
     ['The requested URL was not found on this server'], 'high'),
    ('Tumblr', [r'\.tumblr\.com$'],
     ["There's nothing here", 'Whatever you were looking for'], 'critical'),
    ('WP Engine', [r'\.wpengine\.com$'],
     ["The site you were looking for couldn't be found"], 'critical'),
    ('Bitbucket', [r'\.bitbucket\.io$'],
     ['Repository not found'], 'critical'),
    ('Helpjuice', [r'\.helpjuice\.com$'],
     ["We could not find what you're looking for"], 'critical'),
    ('Tilda', [r'\.tilda\.ws$'],
     ['Please renew your subscription'], 'critical'),
    ('Webflow', [r'proxy-ssl\.webflow\.com$'],
     ["The page you are looking for doesn't exist"], 'high'),
    ('Fly.io', [r'\.fly\.dev$'],
     ['404 Not Found'], 'high'),
    ('Vercel', [r'\.vercel\.app$', r'\.now\.sh$'],
     ['The deployment could not be found on Vercel'], 'critical'),
]


def run_subdomain_takeover_recon(target_url: str, depth: str = 'medium',
                                  subdomains: list = None,
                                  make_request_fn=None, **kwargs) -> dict:
    """
    Detect dangling DNS records across discovered subdomains.

    shallow : Check subdomains from recon_data (no new DNS queries)
    medium  : + Resolve CNAMEs for all discovered subdomains
    deep    : + Full HTTP probe + all fingerprints + MX/NS checks
    """
    start = time.time()
    result = create_result('subdomain_takeover_recon', target_url, depth)
    hostname = extract_hostname(target_url)

    if not subdomains:
        subdomains = [hostname] if hostname else []

    try:
        import dns.resolver
    except ImportError:
        dns = None

    takeover_vulnerabilities = []

    for subdomain in subdomains[:200]:  # Cap
        result['stats']['total_checks'] += 1

        # 1. CNAME resolution
        cname_target = None
        is_nxdomain = False

        if dns and depth in ('medium', 'deep'):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 8
                cname_answers = resolver.resolve(subdomain, 'CNAME')
                cname_target = str(cname_answers[0].target).rstrip('.')
            except Exception:
                pass

            # Check for NXDOMAIN on CNAME target
            if cname_target:
                try:
                    resolver.resolve(cname_target, 'A')
                except dns.resolver.NXDOMAIN:
                    is_nxdomain = True
                    takeover_vulnerabilities.append({
                        'subdomain': subdomain,
                        'cname': cname_target,
                        'type': 'cname_nxdomain',
                        'severity': 'critical',
                        'description': f'CNAME {cname_target} returns NXDOMAIN',
                    })
                    result['stats']['successful_checks'] += 1
                except Exception:
                    pass

        # 2. Check fingerprints against CNAME and/or HTTP response
        if cname_target and not is_nxdomain:
            for service, patterns, fingerprints, severity in TAKEOVER_FINGERPRINTS:
                cname_matches = any(re.search(p, cname_target, re.IGNORECASE)
                                     for p in patterns)
                if cname_matches and make_request_fn and depth in ('medium', 'deep'):
                    # Probe the subdomain
                    for scheme in ('https', 'http'):
                        try:
                            resp = make_request_fn('GET', f'{scheme}://{subdomain}/', timeout=10)
                            if resp and resp.text:
                                body = resp.text
                                for fp in fingerprints:
                                    if fp.lower() in body.lower():
                                        takeover_vulnerabilities.append({
                                            'subdomain': subdomain,
                                            'cname': cname_target,
                                            'service': service,
                                            'type': 'service_fingerprint',
                                            'severity': severity,
                                            'fingerprint': fp[:80],
                                            'description': f'{service} takeover possible',
                                        })
                                        result['stats']['successful_checks'] += 1
                                        break
                        except Exception:
                            continue

        # 3. Deep: NS delegation orphan and MX dangling
        if depth == 'deep' and dns:
            # NS check
            try:
                resolver_obj = dns.resolver.Resolver()
                resolver_obj.timeout = 5
                ns_answers = resolver_obj.resolve(subdomain, 'NS')
                for ns_record in ns_answers:
                    ns_host = str(ns_record.target).rstrip('.')
                    try:
                        resolver_obj.resolve(ns_host, 'A')
                    except dns.resolver.NXDOMAIN:
                        takeover_vulnerabilities.append({
                            'subdomain': subdomain,
                            'ns_target': ns_host,
                            'type': 'ns_delegation_orphan',
                            'severity': 'critical',
                            'description': f'NS {ns_host} returns NXDOMAIN',
                        })
                    except Exception:
                        pass
            except Exception:
                pass

            # MX check
            try:
                mx_answers = resolver_obj.resolve(subdomain, 'MX')
                for mx_record in mx_answers:
                    mx_host = str(mx_record.exchange).rstrip('.')
                    try:
                        resolver_obj.resolve(mx_host, 'A')
                    except dns.resolver.NXDOMAIN:
                        takeover_vulnerabilities.append({
                            'subdomain': subdomain,
                            'mx_target': mx_host,
                            'type': 'mx_dangling',
                            'severity': 'high',
                            'description': f'MX {mx_host} returns NXDOMAIN',
                        })
                    except Exception:
                        pass
            except Exception:
                pass

    # Add findings
    if takeover_vulnerabilities:
        critical = [v for v in takeover_vulnerabilities if v['severity'] == 'critical']
        others = [v for v in takeover_vulnerabilities if v['severity'] != 'critical']

        if critical:
            add_finding(result, {
                'type': 'subdomain_takeover',
                'severity': 'critical',
                'title': f'{len(critical)} critical subdomain takeover(s) possible',
                'details': critical,
            })

        if others:
            add_finding(result, {
                'type': 'subdomain_takeover',
                'severity': 'high',
                'title': f'{len(others)} potential subdomain takeover(s)',
                'details': others,
            })
    else:
        result['stats']['failed_checks'] += len(subdomains)

    # ── External takeover scanners (subjack / SubOver) ──
    try:
        from apps.scanning.engine.tools.wrappers.subjack_wrapper import SubjackTool
        from apps.scanning.engine.tools.wrappers.subover_wrapper import SubOverTool
        _seen_subs = {v['subdomain'] for v in takeover_vulnerabilities}
        _ext_vulns = []
        for _TakeCls in (SubjackTool, SubOverTool):
            try:
                _ext = _TakeCls()
                if _ext.is_available() and subdomains:
                    for _tr in _ext.run('\n'.join(subdomains)):
                        if _tr.host and _tr.host not in _seen_subs:
                            _seen_subs.add(_tr.host)
                            _ext_vulns.append({
                                'subdomain': _tr.host,
                                'type': 'external_scanner',
                                'service': _tr.metadata.get('vulnerable_service', 'unknown'),
                                'severity': 'high',
                                'description': _tr.title,
                                'source': _ext.name,
                            })
            except Exception:
                pass
        if _ext_vulns:
            add_finding(result, {
                'type': 'subdomain_takeover',
                'severity': 'high',
                'title': f'{len(_ext_vulns)} external takeover scanner finding(s)',
                'details': _ext_vulns,
            })
    except Exception:
        pass

    return finalize_result(result, start)
