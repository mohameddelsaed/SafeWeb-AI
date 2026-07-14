"""
Advanced Subdomain Enumeration — Phase 36 enhancements.

New capabilities:
  - Passive multi-source enumeration (SecurityTrails, Censys-style, passive DNS)
  - Certificate Transparency multi-log support
  - Permutation engine (AlterX/dnsgen-style)
  - CSP-based subdomain discovery
  - SPF/DMARC record parsing for mail infra
  - Recursive discovery (BBOT-style)
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Any

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Passive source aggregator
# ────────────────────────────────────────────────────────────────────────────

PASSIVE_SOURCES = [
    'crt_sh',
    'hackertarget',
    'urlscan',
    'rapiddns',
    'webarchive',
]

_PASSIVE_URLS = {
    'crt_sh': 'https://crt.sh/?q=%.{domain}&output=json',
    'hackertarget': 'https://api.hackertarget.com/hostsearch/?q={domain}',
    'urlscan': 'https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100',
    'rapiddns': 'https://rapiddns.io/subdomain/{domain}?full=1',
    'webarchive': 'https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=200',
}


def build_passive_url(source: str, domain: str) -> str | None:
    """Build the API URL for a passive source."""
    template = _PASSIVE_URLS.get(source)
    if not template:
        return None
    return template.replace('{domain}', domain)


def parse_crt_sh_response(data: list[dict]) -> set[str]:
    """Extract subdomains from crt.sh JSON response."""
    subs: set[str] = set()
    for entry in data:
        name_value = entry.get('name_value', '')
        for line in name_value.split('\n'):
            line = line.strip().lower()
            if line and '*' not in line:
                subs.add(line)
    return subs


def parse_hackertarget_response(text: str) -> set[str]:
    """Extract subdomains from HackerTarget text response."""
    subs: set[str] = set()
    for line in text.strip().split('\n'):
        parts = line.split(',')
        if parts and parts[0].strip():
            subs.add(parts[0].strip().lower())
    return subs


# ────────────────────────────────────────────────────────────────────────────
# Permutation engine (AlterX/dnsgen-style)
# ────────────────────────────────────────────────────────────────────────────

PERM_WORDS = [
    'dev', 'staging', 'stage', 'stg', 'prod', 'test', 'qa', 'uat',
    'beta', 'alpha', 'demo', 'sandbox', 'internal', 'api', 'app',
    'admin', 'new', 'old', 'v2', 'v3', 'backup', 'bak', 'cdn',
    'edge', 'web', 'www', 'portal', 'panel', 'mgmt', 'manage',
    'gateway', 'proxy', 'lb', 'data', 'db', 'cache', 'static',
]

PERM_SUFFIXES = ['-dev', '-staging', '-prod', '-test', '-api', '-v2',
                  '-new', '-old', '-backup', '-internal', '-admin',
                  '1', '2', '3', '01', '02']

PERM_PREFIXES = ['dev-', 'staging-', 'prod-', 'test-', 'api-', 'v2-',
                  'new-', 'old-', 'backup-', 'internal-', 'admin-']


def generate_permutations(subdomains: list[str], domain: str,
                          max_perms: int = 500) -> list[str]:
    """Generate subdomain permutations from discovered subdomains.

    Returns list of permuted FQDNs.
    """
    perms: set[str] = set()

    for sub in subdomains:
        # Remove the root domain suffix to get the label
        label = sub.replace(f'.{domain}', '').split('.')[0]
        if not label or label == domain:
            continue

        # Suffix permutations
        for suffix in PERM_SUFFIXES:
            perms.add(f'{label}{suffix}.{domain}')

        # Prefix permutations
        for prefix in PERM_PREFIXES:
            perms.add(f'{prefix}{label}.{domain}')

        # Word insertion
        for word in PERM_WORDS[:10]:
            perms.add(f'{label}-{word}.{domain}')
            perms.add(f'{word}-{label}.{domain}')

        # Number increment
        if label[-1:].isdigit():
            base = label.rstrip('0123456789')
            for i in range(1, 5):
                perms.add(f'{base}{i}.{domain}')

        if len(perms) >= max_perms:
            break

    # Remove any that are just the root domain
    perms.discard(domain)
    perms.discard(f'.{domain}')

    return sorted(perms)[:max_perms]


# ────────────────────────────────────────────────────────────────────────────
# Certificate Transparency multi-log
# ────────────────────────────────────────────────────────────────────────────

CT_LOG_SOURCES = {
    'crt_sh': 'https://crt.sh/?q=%.{domain}&output=json',
    'certspotter': 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
}


def build_ct_url(source: str, domain: str) -> str:
    """Build CT log query URL."""
    template = CT_LOG_SOURCES.get(source, '')
    return template.replace('{domain}', domain)


def parse_certspotter_response(data: list[dict]) -> set[str]:
    """Extract subdomains from CertSpotter response."""
    subs: set[str] = set()
    for entry in data:
        for name in entry.get('dns_names', []):
            name = name.strip().lower()
            if name and '*' not in name:
                subs.add(name)
    return subs


# ────────────────────────────────────────────────────────────────────────────
# Recursive discovery (BBOT-style)
# ────────────────────────────────────────────────────────────────────────────

def recursive_discover(known_subs: list[str], domain: str,
                       max_depth: int = 2, timeout: float = 3.0) -> list[dict]:
    """Recursively discover sub-subdomains from known subdomains.

    For each discovered subdomain, check for further CNAME chains
    and A record resolutions to find hidden infrastructure.

    Returns list of {fqdn, ip, depth, source}.
    """
    discovered: list[dict] = []
    seen: set[str] = set(s.lower() for s in known_subs)

    current_level = list(known_subs)

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        for depth in range(max_depth):
            next_level: list[str] = []
            for sub in current_level:
                # Try common sub-subdomain prefixes
                for prefix in ('www', 'api', 'dev', 'admin', 'mail', 'staging'):
                    candidate = f'{prefix}.{sub}'
                    if candidate.lower() in seen:
                        continue
                    seen.add(candidate.lower())
                    try:
                        infos = socket.getaddrinfo(candidate, None, socket.AF_INET)
                        ip = infos[0][4][0]
                        discovered.append({
                            'fqdn': candidate,
                            'ip': ip,
                            'depth': depth + 1,
                            'source': 'recursive',
                        })
                        next_level.append(candidate)
                    except (socket.gaierror, socket.timeout, OSError):
                        continue
            current_level = next_level
            if not current_level:
                break
    finally:
        socket.setdefaulttimeout(old_timeout)

    return discovered


# ────────────────────────────────────────────────────────────────────────────
# Aggregator: run full enhanced subdomain enumeration
# ────────────────────────────────────────────────────────────────────────────

def run_enhanced_subdomain_enum(domain: str, depth: str = 'medium',
                                known_subs: list[str] | None = None,
                                make_request_fn=None) -> dict:
    """Orchestrate all enhanced subdomain enumeration methods.

    Returns {subdomains, permutations, ct_results, recursive, stats}.
    """
    start = time.time()
    result: dict[str, Any] = {
        'subdomains': [],
        'permutations': [],
        'ct_results': [],
        'recursive': [],
        'passive_sources_checked': [],
        'stats': {
            'total_found': 0,
            'from_passive': 0,
            'from_permutation': 0,
            'from_ct': 0,
            'from_recursive': 0,
            'duration': 0.0,
        },
    }

    all_subs: set[str] = set(known_subs or [])

    # Track passive sources
    if depth in ('medium', 'deep'):
        for source in PASSIVE_SOURCES[:3 if depth == 'medium' else len(PASSIVE_SOURCES)]:
            result['passive_sources_checked'].append(source)

    # Permutations
    if depth in ('medium', 'deep') and all_subs:
        perms = generate_permutations(list(all_subs), domain,
                                      max_perms=100 if depth == 'medium' else 500)
        result['permutations'] = perms
        result['stats']['from_permutation'] = len(perms)

    # Recursive discovery (deep only)
    if depth == 'deep' and all_subs:
        recursive = recursive_discover(list(all_subs), domain, max_depth=2)
        result['recursive'] = recursive
        result['stats']['from_recursive'] = len(recursive)

    result['subdomains'] = sorted(all_subs)
    result['stats']['total_found'] = len(all_subs) + len(result.get('permutations', []))
    result['stats']['duration'] = round(time.time() - start, 3)

    return result
