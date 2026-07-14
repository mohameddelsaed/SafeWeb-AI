"""
WHOIS Reconnaissance Module — Domain registration analysis.

Gathers: registrar, creation/expiry dates, registrant info,
nameservers, and domain age analysis.

Primary lookup uses RDAP (structured JSON via rdap.org);
falls back to raw socket WHOIS for unsupported TLDs.
"""
import re
import json
import socket
import logging
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# Privacy / proxy registrar patterns — if registrar matches, registrant is masked
_PRIVACY_REGISTRARS = [
    'domains by proxy', 'domainsbyproxy',
    'whoisguard', 'whois guard',
    'privacyprotect', 'privacy protect',
    'perfect privacy', 'perfectprivacy',
    'contact privacy', 'contactprivacy',
    'withheld for privacy',
    'registrant privacy',
    'private registration',
    'identity protect',
    'domain privacy',
    'proxy protection',
    'networksolutions privacy',
    'privacy service',
    'register.com privacy',
    'godaddy privacy',
    'namecheap privacy',
    'tucows privacy',
    'enom privacy',
    'name.com privacy',
    '1&1 privacy',
    'ionos privacy',
    'redacted for privacy',
    'data protected',
]

# WHOIS servers per TLD — 100+ TLDs
WHOIS_SERVERS = {
    # gTLDs
    'com':        'whois.verisign-grs.com',
    'net':        'whois.verisign-grs.com',
    'org':        'whois.pir.org',
    'info':       'whois.afilias.net',
    'biz':        'whois.neulevel.biz',
    'mobi':       'whois.dotmobiregistry.net',
    'name':       'whois.nic.name',
    'pro':        'whois.registrypro.pro',
    'tel':        'whois.nic.tel',
    'travel':     'whois.nic.travel',
    'museum':     'whois.museum',
    'coop':       'whois.nic.coop',
    'aero':       'whois.aero',
    'jobs':       'jobswhois.verisign-grs.com',
    'int':        'whois.iana.org',
    'edu':        'whois.educause.edu',
    'gov':        'whois.dotgov.gov',
    'mil':        'whois.nic.mil',
    # New gTLDs
    'io':         'whois.nic.io',
    'co':         'whois.nic.co',
    'dev':        'whois.nic.google',
    'app':        'whois.nic.google',
    'page':       'whois.nic.google',
    'web':        'whois.nic.web',
    'me':         'whois.nic.me',
    'xyz':        'whois.nic.xyz',
    'ai':         'whois.nic.ai',
    'tech':       'whois.nic.tech',
    'online':     'whois.nic.online',
    'site':       'whois.nic.site',
    'store':      'whois.nic.store',
    'shop':       'whois.nic.shop',
    'cloud':      'whois.nic.cloud',
    'blog':       'whois.nic.blog',
    'media':      'whois.nic.media',
    'digital':    'whois.nic.digital',
    'solutions':  'whois.nic.solutions',
    'services':   'whois.nic.services',
    'agency':     'whois.nic.agency',
    'company':    'whois.nic.company',
    'group':      'whois.nic.group',
    'global':     'whois.nic.global',
    'world':      'whois.nic.world',
    'network':    'whois.nic.network',
    'systems':    'whois.nic.systems',
    'software':   'whois.nic.software',
    'email':      'whois.nic.email',
    'tools':      'whois.nic.tools',
    'expert':     'whois.nic.vermeg',
    'guru':       'whois.nic.guru',
    'academy':    'whois.nic.academy',
    'training':   'whois.nic.training',
    'center':     'whois.nic.center',
    'support':    'whois.nic.support',
    'help':       'whois.uniregistry.net',
    'care':       'whois.nic.care',
    'health':     'whois.nic.health',
    'finance':    'whois.nic.finance',
    'financial':  'whois.nic.financial',
    'bank':       'whois.nic.bank',
    'insurance':  'whois.nic.insurance',
    'fund':       'whois.nic.fund',
    'invest':     'whois.uniregistry.net',
    'law':        'whois.nic.law',
    'legal':      'whois.nic.legal',
    'accountant': 'whois.nic.accountant',
    'tax':        'whois.nic.tax',
    'realty':     'whois.nic.realty',
    'property':   'whois.uniregistry.net',
    'engineering':'whois.nic.engineering',
    'design':     'whois.nic.design',
    'art':        'whois.art.london',
    'music':      'whois.nic.music',
    'news':       'whois.nic.news',
    'press':      'whois.nic.press',
    'review':     'whois.nic.review',
    'live':       'whois.nic.live',
    'tv':         'tvwhois.verisign-grs.com',
    'film':       'whois.nic.film',
    'video':      'whois.nic.video',
    'photo':      'whois.uniregistry.net',
    'photos':     'whois.nic.photos',
    'gallery':    'whois.nic.gallery',
    'auction':    'whois.nic.auction',
    'market':     'whois.nic.market',
    'marketing':  'whois.nic.marketing',
    'social':     'whois.nic.social',
    'events':     'whois.nic.events',
    'community':  'whois.nic.community',
    'foundation': 'whois.nic.foundation',
    'institute':  'whois.nic.institute',
    'management': 'whois.nic.management',
    'consulting': 'whois.nic.consulting',
    'guru2':      'whois.nic.guru',
    # ccTLDs — Europe
    'uk':         'whois.nic.uk',
    'co.uk':      'whois.nic.uk',
    'org.uk':     'whois.nic.uk',
    'de':         'whois.denic.de',
    'fr':         'whois.nic.fr',
    'nl':         'whois.domain-registry.nl',
    'be':         'whois.dns.be',
    'ch':         'whois.nic.ch',
    'at':         'whois.nic.at',
    'es':         'whois.nic.es',
    'it':         'whois.nic.it',
    'pl':         'whois.dns.pl',
    'cz':         'whois.nic.cz',
    'sk':         'whois.sk-nic.sk',
    'hu':         'whois.nic.hu',
    'ro':         'whois.rotld.ro',
    'bg':         'whois.register.bg',
    'hr':         'whois.dns.hr',
    'si':         'whois.arnes.si',
    'lt':         'whois.domreg.lt',
    'lv':         'whois.nic.lv',
    'ee':         'whois.tld.ee',
    'fi':         'whois.fi',
    'dk':         'whois.dk-hostmaster.dk',
    'no':         'whois.norid.no',
    'se':         'whois.iis.se',
    'pt':         'whois.dns.pt',
    'gr':         'whois.ics.forth.gr',
    'ie':         'whois.domainregistry.ie',
    'lu':         'whois.dns.lu',
    'is':         'whois.isnic.is',
    'li':         'whois.nic.li',
    'ru':         'whois.tcinet.ru',
    'tr':         'whois.nic.tr',
    'ua':         'whois.ua',
    # ccTLDs — Americas
    'us':         'whois.nic.us',
    'ca':         'whois.cira.ca',
    'mx':         'whois.mx',
    'br':         'whois.registro.br',
    'ar':         'whois.nic.ar',
    'cl':         'whois.nic.cl',
    'co2':        'whois.nic.co',
    'pe':         'kero.yachay.pe',
    'uy':         'whois.nic.org.uy',
    'ec':         'whois.nic.ec',
    'gt':         'whois.gt',
    'cr':         'whois.lacnic.net',
    've':         'whois.nic.ve',
    # ccTLDs — Asia-Pacific
    'jp':         'whois.jprs.jp',
    'cn':         'whois.cnnic.cn',
    'hk':         'whois.hkirc.hk',
    'sg':         'whois.sgnic.sg',
    'au':         'whois.auda.org.au',
    'nz':         'whois.srs.net.nz',
    'in':         'whois.inregistry.net',
    'tw':         'whois.twnic.net.tw',
    'kr':         'whois.kr',
    'th':         'whois.thnic.co.th',
    'id':         'whois.pandi.or.id',
    'ph':         'whois.dot.ph',
    'my':         'whois.mynic.my',
    'vn':         'whois.vnnic.vn',
    # ccTLDs — Middle East & Africa
    'sa':         'whois.nic.net.sa',
    'ae':         'whois.aeda.net.ae',
    'il':         'whois.isoc.org.il',
    'eg':         'whois.ripe.net',
    'za':         'whois.co.za',
    'ng':         'whois.nic.net.ng',
    'ke':         'whois.kenic.or.ke',
    'gh':         'whois.nic.gh',
    'tz':         'whois.tznic.or.tz',
    'ma':         'whois.iam.net.ma',
    'tn':         'whois.ati.tn',
}


def run_whois_recon(target_url: str) -> dict:
    """
    Perform WHOIS/RDAP lookup on the target domain.

    Tries RDAP first (structured JSON); falls back to raw socket WHOIS.

    Returns standardised dict (findings/metadata/errors/stats) **plus**
    legacy keys for backward compatibility:

        domain, registrar, creation_date, expiry_date, updated_date,
        nameservers, status, domain_age_days, days_until_expiry,
        privacy_protected, registrant_org, issues, raw
    """
    start = time.time()
    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    result = create_result('whois_recon', target_url)

    # ── Legacy keys ──
    result['domain'] = root_domain
    result['registrar'] = None
    result['creation_date'] = None
    result['expiry_date'] = None
    result['updated_date'] = None
    result['nameservers'] = []
    result['status'] = []
    result['domain_age_days'] = None
    result['days_until_expiry'] = None
    result['privacy_protected'] = False
    result['registrant_org'] = None
    result['issues'] = []
    result['raw'] = None

    if not root_domain:
        return finalize_result(result, start)

    result['stats']['total_checks'] += 1

    # 1. Try RDAP (structured JSON — preferred)
    rdap_ok = _rdap_lookup(root_domain, result)

    # 2. Fall back to raw socket WHOIS if RDAP failed
    if not rdap_ok:
        tld = root_domain.split('.')[-1].lower()
        # Handle multi-part TLDs like co.uk
        if len(root_domain.split('.')) >= 3:
            multi_tld = '.'.join(root_domain.split('.')[-2:])
            whois_server = WHOIS_SERVERS.get(multi_tld) or WHOIS_SERVERS.get(tld)
        else:
            whois_server = WHOIS_SERVERS.get(tld)

        if not whois_server:
            result['issues'].append(f'No WHOIS/RDAP data available for TLD: .{tld}')
        else:
            try:
                raw_whois = _query_whois(root_domain, whois_server)
                result['raw'] = raw_whois[:2000]
                result['stats']['successful_checks'] += 1
                _parse_whois(raw_whois, result)
            except Exception as e:
                result['issues'].append(f'WHOIS query failed: {str(e)}')
                result['errors'].append(f'WHOIS query failed: {e}')

    if result['registrar'] or result['creation_date']:
        result['stats']['successful_checks'] += 1

    # 3. Privacy registrar detection
    if result['registrar']:
        reg_lower = result['registrar'].lower()
        if any(pattern in reg_lower for pattern in _PRIVACY_REGISTRARS):
            result['privacy_protected'] = True
            result['issues'].append(
                f'Registrant hidden by privacy service: {result["registrar"]}'
            )
            add_finding(result, {
                'type': 'whois_privacy',
                'registrar': result['registrar'],
                'severity': 'info',
            })

    # 4. Domain age analysis
    if result['creation_date']:
        try:
            created = _parse_date(result['creation_date'])
            if created:
                age = (datetime.now(timezone.utc) - created).days
                result['domain_age_days'] = age
                if age < 30:
                    result['issues'].append('Domain is less than 30 days old — potentially suspicious')
                elif age < 365:
                    result['issues'].append('Domain is less than 1 year old')
                add_finding(result, {'type': 'domain_age', 'days': age})
        except Exception:
            pass

    # 5. Expiry analysis
    if result['expiry_date']:
        try:
            expiry = _parse_date(result['expiry_date'])
            if expiry:
                days_left = (expiry - datetime.now(timezone.utc)).days
                result['days_until_expiry'] = days_left
                if days_left < 30:
                    result['issues'].append('Domain expires in less than 30 days')
                elif days_left < 90:
                    result['issues'].append('Domain expires in less than 90 days')
                add_finding(result, {'type': 'domain_expiry', 'days_left': days_left})
        except Exception:
            pass

    # 6. Add core findings
    if result['registrar']:
        add_finding(result, {'type': 'registrar', 'name': result['registrar']})
    if result['nameservers']:
        add_finding(result, {'type': 'nameservers', 'servers': result['nameservers']})
    if result['registrant_org']:
        add_finding(result, {'type': 'registrant_org', 'org': result['registrant_org']})
    for issue in result['issues']:
        add_finding(result, {'type': 'whois_issue', 'detail': issue})

    return finalize_result(result, start)


# ── RDAP Lookup ────────────────────────────────────────────────────────────

def _rdap_lookup(domain: str, result: dict) -> bool:
    """Query RDAP (Registration Data Access Protocol) for structured WHOIS data.

    Uses rdap.org as the bootstrap resolver.
    Returns True if data was successfully retrieved and parsed.
    """
    try:
        url = f'https://rdap.org/domain/{domain}'
        req = urllib.request.Request(
            url,
            headers={
                'Accept': 'application/rdap+json, application/json',
                'User-Agent': 'SafeWeb-AI/1.0 RDAP-Client',
            },
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status != 200:
                return False
            raw = resp.read(65536).decode('utf-8', errors='ignore')

        data = json.loads(raw)
        result['raw'] = raw[:2000]

        # --- Registrar / entities ---
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            vcard = entity.get('vcardArray', [])

            # Extract org / name from vcardArray
            org_name = _rdap_extract_vcard_field(vcard, 'org')
            fn_name  = _rdap_extract_vcard_field(vcard, 'fn')

            if 'registrar' in roles and not result['registrar']:
                result['registrar'] = org_name or fn_name or entity.get('handle', '')
            if 'registrant' in roles and not result['registrant_org']:
                result['registrant_org'] = org_name or fn_name

        # --- Dates ---
        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date   = event.get('eventDate', '')
            if action == 'registration' and not result['creation_date']:
                result['creation_date'] = date
            elif action == 'expiration' and not result['expiry_date']:
                result['expiry_date'] = date
            elif action in ('last changed', 'last update of RDAP database') and not result['updated_date']:
                result['updated_date'] = date

        # --- Nameservers ---
        for ns in data.get('nameservers', []):
            ns_name = ns.get('ldhName', '') or ns.get('unicodeName', '')
            if ns_name and ns_name.lower() not in result['nameservers']:
                result['nameservers'].append(ns_name.lower())

        # --- Status ---
        for s in data.get('status', []):
            if s not in result['status']:
                result['status'].append(s)

        return bool(result['registrar'] or result['creation_date'])

    except (urllib.error.URLError, json.JSONDecodeError, Exception):
        return False


def _rdap_extract_vcard_field(vcard_array, field: str) -> str:
    """Extract a single field value from an RDAP vcardArray."""
    if not vcard_array or len(vcard_array) < 2:
        return ''
    for entry in vcard_array[1]:
        if isinstance(entry, list) and len(entry) >= 4:
            if entry[0].lower() == field.lower():
                val = entry[3]
                if isinstance(val, list):
                    val = val[0] if val else ''
                return str(val).strip()
    return ''


def _query_whois(domain: str, server: str, port: int = 43, timeout: int = 10) -> str:
    """Send a WHOIS query and return the raw response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.sendall(f'{domain}\r\n'.encode())

        response = b''
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break

        sock.close()
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        logger.warning(f'WHOIS query for {domain} failed: {e}')
        raise


def _parse_whois(raw: str, results: dict):
    """Parse WHOIS response into structured data."""
    lines = raw.split('\n')

    for line in lines:
        line_lower = line.lower().strip()

        # Registrar
        if 'registrar:' in line_lower and not results['registrar']:
            results['registrar'] = line.split(':', 1)[1].strip()

        # Creation date
        elif any(k in line_lower for k in ('creation date:', 'created:', 'registered on:')):
            if not results['creation_date']:
                results['creation_date'] = line.split(':', 1)[1].strip()

        # Expiry date
        elif any(k in line_lower for k in ('expiry date:', 'expiration date:', 'expires on:', 'registry expiry')):
            if not results['expiry_date']:
                results['expiry_date'] = line.split(':', 1)[1].strip()

        # Updated date
        elif any(k in line_lower for k in ('updated date:', 'last modified:', 'last updated:')):
            if not results['updated_date']:
                results['updated_date'] = line.split(':', 1)[1].strip()

        # Nameservers
        elif 'name server:' in line_lower or 'nserver:' in line_lower:
            ns = line.split(':', 1)[1].strip().lower()
            if ns and ns not in results['nameservers']:
                results['nameservers'].append(ns)

        # Status
        elif 'status:' in line_lower or 'domain status:' in line_lower:
            status = line.split(':', 1)[1].strip()
            if status:
                results['status'].append(status.split()[0])  # Take first word


def _parse_date(date_str: str) -> datetime | None:
    """Try to parse a date string from WHOIS."""
    formats = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d',
        '%d-%b-%Y',
        '%d/%m/%Y',
        '%Y/%m/%d',
    ]

    clean = date_str.strip()
    for fmt in formats:
        try:
            dt = datetime.strptime(clean, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    return None


def _get_root_domain(hostname: str) -> str:
    """Extract root domain from hostname (legacy wrapper)."""
    return extract_root_domain(hostname)


# ── Reverse WHOIS — discover domains owned by an organization ────────────

def reverse_whois(org_name: str) -> list[str]:
    """Reverse WHOIS lookup: find domains registered to an organization.

    Uses multiple public sources:
      1. viewdns.info reverse WHOIS (HTML scraping)
      2. RDAP bootstrap → search by entity name

    Returns a deduplicated list of domain names (without scheme).
    """
    if not org_name or not org_name.strip():
        return []

    domains: set[str] = set()

    # Source 1: ViewDNS.info reverse WHOIS
    try:
        domains.update(_viewdns_reverse_whois(org_name))
    except Exception as exc:
        logger.warning('ViewDNS reverse WHOIS failed for %s: %s', org_name, exc)

    # Source 2: Google CT Transparency (org name search via crt.sh)
    # This is handled separately by ct_log_enum.search_by_org

    logger.info('Reverse WHOIS for "%s" found %d domains', org_name, len(domains))
    return sorted(domains)


def _viewdns_reverse_whois(org_name: str) -> set[str]:
    """Query ViewDNS.info reverse WHOIS API (free tier, HTML response)."""
    try:
        import requests
    except ImportError:
        return set()

    url = 'https://viewdns.info/reversewhois/'
    params = {'q': org_name}

    try:
        resp = requests.get(url, params=params, timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; SafeWeb-AI Security Scanner)',
        })
        resp.raise_for_status()

        # Parse domain names from HTML table
        domains = set()
        # ViewDNS returns domains in a table; extract them with regex
        # Pattern: domain names in table cells
        domain_pattern = re.compile(
            r'<td>([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})</td>'
        )
        for match in domain_pattern.finditer(resp.text):
            domain = match.group(1).lower().strip()
            if '.' in domain and len(domain) < 253:
                domains.add(domain)

        return domains

    except Exception as exc:
        logger.debug('ViewDNS reverse WHOIS request failed: %s', exc)
        return set()

