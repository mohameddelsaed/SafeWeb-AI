"""
Advanced DNS Recon — Phase 36 enhancements to DNS reconnaissance.

New capabilities:
  - DNS zone transfer attempts (AXFR)
  - DNSSEC validation chain checking
  - DNS-over-HTTPS (DoH) support
  - Wildcard detection & filtering (puredns-style)
  - DNS brute-force with massdns-compatible resolved filter
  - SPF/DMARC/BIMI deep parsing
"""
from __future__ import annotations

import logging
import re
import socket
import time
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# DNSSEC validation
# ────────────────────────────────────────────────────────────────────────────

DNSSEC_ALGORITHMS = {
    1: 'RSA/MD5 (deprecated)',
    3: 'DSA/SHA-1',
    5: 'RSA/SHA-1',
    7: 'RSASHA1-NSEC3-SHA1',
    8: 'RSA/SHA-256',
    10: 'RSA/SHA-512',
    13: 'ECDSA/P-256/SHA-256',
    14: 'ECDSA/P-384/SHA-384',
    15: 'Ed25519',
    16: 'Ed448',
}

WEAK_DNSSEC_ALGORITHMS = {1, 3, 5, 7}  # MD5/SHA-1 based


def check_dnssec(domain: str) -> dict:
    """Check DNSSEC deployment status for a domain.

    Returns dict with keys: enabled, has_dnskey, has_ds, has_rrsig,
    algorithm, algorithm_name, issues.
    """
    result: dict[str, Any] = {
        'enabled': False,
        'has_dnskey': False,
        'has_ds': False,
        'has_rrsig': False,
        'algorithm': None,
        'algorithm_name': None,
        'issues': [],
    }
    try:
        import dns.resolver
        import dns.rdatatype
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        # Check DNSKEY
        try:
            dnskey_ans = resolver.resolve(domain, 'DNSKEY')
            result['has_dnskey'] = True
            for rr in dnskey_ans:
                alg = rr.algorithm
                result['algorithm'] = alg
                result['algorithm_name'] = DNSSEC_ALGORITHMS.get(alg, f'Unknown ({alg})')
                if alg in WEAK_DNSSEC_ALGORITHMS:
                    result['issues'].append(
                        f'Weak DNSSEC algorithm: {result["algorithm_name"]}'
                    )
        except Exception:
            pass

        # Check DS record
        try:
            resolver.resolve(domain, 'DS')
            result['has_ds'] = True
        except Exception:
            pass

        # Check RRSIG
        try:
            resolver.resolve(domain, 'RRSIG')
            result['has_rrsig'] = True
        except Exception:
            pass

        result['enabled'] = result['has_dnskey'] and result['has_ds']

    except ImportError:
        # dnspython not available — fallback: just report unknown
        result['issues'].append('dnspython not installed; DNSSEC check skipped')
    except Exception as exc:
        result['issues'].append(f'DNSSEC check error: {exc}')

    return result


# ────────────────────────────────────────────────────────────────────────────
# Zone transfer (AXFR)
# ────────────────────────────────────────────────────────────────────────────

def attempt_zone_transfer(domain: str, nameservers: list[str] | None = None,
                          timeout: float = 10.0) -> dict:
    """Attempt AXFR zone transfer against nameservers.

    Returns dict: {vulnerable, nameserver, records, error}.
    """
    result: dict[str, Any] = {
        'vulnerable': False,
        'nameserver': None,
        'records': [],
        'error': None,
    }

    # Get nameservers
    ns_list = nameservers or []
    if not ns_list:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'NS')
            ns_list = [str(rr.target).rstrip('.') for rr in answers]
        except ImportError:
            result['error'] = 'dnspython not installed'
            return result
        except Exception as exc:
            result['error'] = f'NS lookup failed: {exc}'
            return result

    for ns in ns_list[:5]:  # Limit
        try:
            import dns.query
            import dns.zone
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_ip, domain, timeout=timeout)
            )
            records = []
            for name, node in zone.nodes.items():
                records.append(str(name))
            if records:
                result['vulnerable'] = True
                result['nameserver'] = ns
                result['records'] = records[:500]  # Cap
                break
        except ImportError:
            result['error'] = 'dnspython not installed'
            break
        except Exception:
            continue

    return result


# ────────────────────────────────────────────────────────────────────────────
# DNS-over-HTTPS (DoH) resolver
# ────────────────────────────────────────────────────────────────────────────

DOH_PROVIDERS = {
    'cloudflare': 'https://cloudflare-dns.com/dns-query',
    'google': 'https://dns.google/resolve',
    'quad9': 'https://dns.quad9.net:5053/dns-query',
}


def resolve_doh(domain: str, record_type: str = 'A',
                provider: str = 'cloudflare',
                timeout: float = 5.0) -> dict:
    """Resolve domain using DNS-over-HTTPS.

    Returns {answers: list[str], provider, status, error}.
    """
    import json
    from urllib.request import Request, urlopen
    from urllib.error import URLError

    base_url = DOH_PROVIDERS.get(provider, DOH_PROVIDERS['cloudflare'])
    url = f'{base_url}?name={domain}&type={record_type}'

    result: dict[str, Any] = {
        'answers': [],
        'provider': provider,
        'status': None,
        'error': None,
    }

    try:
        req = Request(url, headers={
            'Accept': 'application/dns-json',
        })
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            result['status'] = data.get('Status', -1)
            for answer in data.get('Answer', []):
                result['answers'].append(answer.get('data', ''))
    except (URLError, OSError, json.JSONDecodeError) as exc:
        result['error'] = str(exc)

    return result


# ────────────────────────────────────────────────────────────────────────────
# SPF / DMARC / BIMI deep parser
# ────────────────────────────────────────────────────────────────────────────

SPF_QUALIFIERS = {'+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral'}


def parse_spf(txt_records: list[str]) -> dict:
    """Parse SPF record from TXT records.

    Returns {found, version, mechanisms, includes, all_qualifier, issues}.
    """
    result: dict[str, Any] = {
        'found': False,
        'version': None,
        'mechanisms': [],
        'includes': [],
        'all_qualifier': None,
        'issues': [],
    }

    for record in txt_records:
        if record.startswith('v=spf1'):
            result['found'] = True
            result['version'] = 'spf1'
            tokens = record.split()
            for token in tokens[1:]:
                if token.startswith('include:'):
                    result['includes'].append(token[8:])
                elif token.startswith('+all') or token == 'all':
                    result['all_qualifier'] = 'pass'
                    result['issues'].append('SPF +all allows any sender (dangerous)')
                elif token.startswith('~all'):
                    result['all_qualifier'] = 'softfail'
                elif token.startswith('-all'):
                    result['all_qualifier'] = 'fail'
                elif token.startswith('?all'):
                    result['all_qualifier'] = 'neutral'
                    result['issues'].append('SPF ?all is neutral (weak)')
                else:
                    result['mechanisms'].append(token)

            if not result['all_qualifier']:
                result['issues'].append('SPF record missing "all" mechanism')
            break

    return result


def parse_dmarc(txt_records: list[str]) -> dict:
    """Parse DMARC record from _dmarc TXT records.

    Returns {found, version, policy, subdomain_policy, pct, rua, ruf, issues}.
    """
    result: dict[str, Any] = {
        'found': False,
        'version': None,
        'policy': None,
        'subdomain_policy': None,
        'pct': 100,
        'rua': [],
        'ruf': [],
        'issues': [],
    }

    for record in txt_records:
        if record.startswith('v=DMARC1'):
            result['found'] = True
            result['version'] = 'DMARC1'
            tags = [t.strip() for t in record.split(';') if t.strip()]
            for tag in tags:
                if tag.startswith('p='):
                    result['policy'] = tag[2:]
                elif tag.startswith('sp='):
                    result['subdomain_policy'] = tag[3:]
                elif tag.startswith('pct='):
                    try:
                        result['pct'] = int(tag[4:])
                    except ValueError:
                        pass
                elif tag.startswith('rua='):
                    result['rua'] = [u.strip() for u in tag[4:].split(',')]
                elif tag.startswith('ruf='):
                    result['ruf'] = [u.strip() for u in tag[4:].split(',')]

            if result['policy'] == 'none':
                result['issues'].append('DMARC policy is "none" — no enforcement')
            if result['pct'] < 100:
                result['issues'].append(
                    f'DMARC only applied to {result["pct"]}% of messages'
                )
            if not result['rua']:
                result['issues'].append('No aggregate report URI (rua) configured')
            break

    return result


# ────────────────────────────────────────────────────────────────────────────
# Wildcard DNS detection
# ────────────────────────────────────────────────────────────────────────────

import random
import string


def detect_wildcard(domain: str, probe_count: int = 5) -> dict:
    """Detect wildcard DNS configuration for a domain.

    Returns {is_wildcard, wildcard_ips, error}.
    """
    result: dict[str, Any] = {
        'is_wildcard': False,
        'wildcard_ips': [],
        'error': None,
    }

    resolved_ips: list[str] = []
    for _ in range(probe_count):
        label = ''.join(random.choices(string.ascii_lowercase, k=12))
        fqdn = f'{label}.{domain}'
        try:
            infos = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            ip = infos[0][4][0]
            resolved_ips.append(ip)
        except (socket.gaierror, OSError):
            pass

    if len(resolved_ips) == probe_count:
        # All random subdomains resolved — likely wildcard
        unique_ips = set(resolved_ips)
        result['is_wildcard'] = True
        result['wildcard_ips'] = list(unique_ips)

    return result


# ────────────────────────────────────────────────────────────────────────────
# DNS brute-force with filter (massdns-style)
# ────────────────────────────────────────────────────────────────────────────

DEFAULT_DNS_WORDLIST = [
    'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
    'portal', 'vpn', 'remote', 'blog', 'shop', 'cdn', 'app', 'login',
    'secure', 'ns1', 'ns2', 'mx', 'mx1', 'mx2', 'imap', 'pop',
    'smtp', 'webmail', 'cloud', 'git', 'ci', 'jenkins', 'jira',
    'grafana', 'prometheus', 'kibana', 'elastic', 'redis', 'db',
    'mongo', 'mysql', 'postgres', 'backup', 'old', 'new', 'beta',
    'alpha', 'demo', 'sandbox', 'internal', 'intranet', 'extranet',
    'status', 'monitor', 'docs', 'wiki', 'help', 'support', 'auth',
    'sso', 'oauth', 'iam', 'vault', 'consul', 'registry', 'hub',
    'files', 'upload', 'download', 'assets', 'static', 'images',
    'media', 'video', 'stream', 'chat', 'forum', 'community',
]


def dns_brute_force(domain: str, wordlist: list[str] | None = None,
                    wildcard_ips: list[str] | None = None,
                    timeout: float = 3.0) -> dict:
    """Brute-force subdomains with optional wildcard filtering.

    Returns {found: list[{fqdn, ip}], wildcard_filtered, total_checked, error}.
    """
    words = wordlist or DEFAULT_DNS_WORDLIST
    wc_ips = set(wildcard_ips or [])

    result: dict[str, Any] = {
        'found': [],
        'wildcard_filtered': 0,
        'total_checked': 0,
        'error': None,
    }

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        for word in words:
            fqdn = f'{word}.{domain}'
            result['total_checked'] += 1
            try:
                infos = socket.getaddrinfo(fqdn, None, socket.AF_INET)
                ip = infos[0][4][0]
                if ip in wc_ips:
                    result['wildcard_filtered'] += 1
                    continue
                result['found'].append({'fqdn': fqdn, 'ip': ip})
            except (socket.gaierror, socket.timeout, OSError):
                continue
    finally:
        socket.setdefaulttimeout(old_timeout)

    return result


# ────────────────────────────────────────────────────────────────────────────
# CSP-based domain discovery
# ────────────────────────────────────────────────────────────────────────────

_CSP_DIRECTIVE_RE = re.compile(r'(?:default-src|script-src|connect-src|img-src|'
                               r'style-src|font-src|frame-src|media-src|object-src'
                               r'|worker-src|child-src)\s+([^;]+)', re.I)


def extract_csp_domains(csp_header: str) -> list[str]:
    """Extract domains from a Content-Security-Policy header value.

    Returns deduplicated list of domain names found in CSP directives.
    """
    domains: set[str] = set()
    for match in _CSP_DIRECTIVE_RE.finditer(csp_header):
        sources = match.group(1).split()
        for src in sources:
            src = src.strip("'\"")
            if src.startswith(('http://', 'https://')):
                parsed = urlparse(src)
                if parsed.hostname:
                    domains.add(parsed.hostname)
            elif re.match(r'^[a-zA-Z0-9*][\w.*-]+\.[a-zA-Z]{2,}$', src):
                domains.add(src.lstrip('*.'))
    return sorted(domains)
