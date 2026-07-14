"""
Subdomain Enumeration Module — Active DNS-based subdomain discovery.

Enhanced with:
    • Brute-force DNS resolution from wordlists (original)
    • Wildcard baseline detection before scanning
    • DNS permutation engine (character swaps, digit appends, keyword inserts)
    • Smart deduplication against known/passive subdomains

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import random
import socket
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
    load_data_lines,
)
try:
    from ..payloads.seclists_manager import SecListsManager as _SecListsManager
    _SECLISTS = _SecListsManager()
except Exception:
    _SECLISTS = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Thread pool sizing
_MAX_WORKERS = 30

# DNS resolution timeout per host (seconds)
_RESOLVE_TIMEOUT = 3

# Wordlist mapping by depth
_WORDLIST_MAP = {
    'quick': 'subdomain_wordlist_100.txt',
    'shallow': 'subdomain_wordlist_100.txt',
    'medium': 'subdomain_wordlist_1000.txt',
    'deep': 'subdomain_wordlist_10000.txt',
}

# Permutation keywords commonly found in infra
_PERM_KEYWORDS = [
    'dev', 'staging', 'stage', 'stg', 'prod', 'production', 'uat',
    'test', 'testing', 'qa', 'beta', 'alpha', 'demo', 'sandbox',
    'internal', 'priv', 'private', 'ext', 'external', 'public',
    'old', 'new', 'v2', 'v3', 'backup', 'bak', 'temp', 'tmp',
    'api', 'app', 'web', 'www', 'portal', 'admin', 'panel',
    'edge', 'cdn', 'static', 'assets', 'media', 'images',
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _resolve_subdomain(fqdn: str) -> dict | None:
    """Attempt to resolve *fqdn* and return ``{name, ip}`` or *None*."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_RESOLVE_TIMEOUT)
        results = socket.getaddrinfo(fqdn, None, socket.AF_INET)
        if results:
            ip = results[0][4][0]
            return {'name': fqdn, 'ip': ip}
    except socket.gaierror:
        return None
    except socket.timeout:
        logger.debug('DNS timeout resolving %s', fqdn)
        return None
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
    return None


# ── Wildcard Baseline Detection ───────────────────────────────────────────

def _detect_wildcard(root_domain: str, num_probes: int = 5) -> str | None:
    """Probe random non-existent subdomains to detect wildcard DNS.

    Returns the wildcard IP if detected, otherwise ``None``.
    """
    random_labels = [
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        for _ in range(num_probes)
    ]
    resolved_ips: dict[str, int] = {}
    for label in random_labels:
        fqdn = f'{label}.{root_domain}'
        res = _resolve_subdomain(fqdn)
        if res:
            ip = res['ip']
            resolved_ips[ip] = resolved_ips.get(ip, 0) + 1

    # If >=80% of random probes resolve to the SAME IP → wildcard
    for ip, count in resolved_ips.items():
        if count >= num_probes * 0.8:
            logger.info('Wildcard DNS detected: *.%s → %s', root_domain, ip)
            return ip
    return None


# ── Permutation Engine ────────────────────────────────────────────────────

def _generate_permutations(known_subdomains: list[str], root_domain: str,
                           max_perms: int = 2000) -> list[str]:
    """Generate permutation candidates from known subdomain prefixes.

    Techniques:
        1. Keyword prepend/append (dev-api, api-dev, api-staging)
        2. Digit suffixes (api1, api2, api01)
        3. Character swap (single char replacement)
        4. Dot insertion (api.dev → api-dev)
        5. Hyphen toggle (api-v2 ↔ apiv2)
    """
    # Extract prefix labels from known subdomains
    base_labels: set[str] = set()
    for sub in known_subdomains:
        if isinstance(sub, dict):
            sub = sub.get('name', sub.get('subdomain', ''))
        label = sub.replace(f'.{root_domain}', '').split('.')[0].lower().strip()
        if label and len(label) < 40:
            base_labels.add(label)

    if not base_labels:
        return []

    perms: set[str] = set()

    for label in base_labels:
        # 1. Keyword prepend/append
        for kw in _PERM_KEYWORDS:
            if kw == label:
                continue
            perms.add(f'{kw}-{label}')
            perms.add(f'{label}-{kw}')
            perms.add(f'{kw}{label}')
            perms.add(f'{label}{kw}')

        # 2. Digit suffixes
        for d in range(0, 10):
            perms.add(f'{label}{d}')
            perms.add(f'{label}-{d}')
        for d in ['01', '02', '03', '001', '002']:
            perms.add(f'{label}{d}')

        # 3. Hyphen toggle
        if '-' in label:
            perms.add(label.replace('-', ''))
            perms.add(label.replace('-', '.'))
        else:
            # Try inserting hyphens between word parts
            for i in range(1, len(label)):
                if label[i-1].isalpha() and label[i].isdigit():
                    perms.add(f'{label[:i]}-{label[i:]}')
                elif label[i-1].isdigit() and label[i].isalpha():
                    perms.add(f'{label[:i]}-{label[i:]}')

    # Remove any that are already known
    perms -= base_labels

    result = sorted(perms)
    if len(result) > max_perms:
        result = result[:max_perms]

    logger.info('Permutation engine: %d candidates from %d base labels', len(result), len(base_labels))
    return result


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_subdomain_enum(target_url: str, depth: str = 'medium',
                       known_subdomains: list | None = None) -> dict:
    """Enumerate subdomains by brute-forcing DNS resolution.

    Args:
        target_url:       The target URL to analyse.
        depth:            Scan depth — ``'quick'``, ``'medium'``, or ``'deep'``.
        known_subdomains: Previously discovered subdomains (for permutation).

    Returns:
        Standardised result dict with legacy keys:
        ``domain``, ``subdomains``, ``total_found``, ``wordlist_size``,
        ``wildcard_ip``, ``permutation_count``.
    """
    start = time.time()
    result = create_result('subdomain_enum', target_url, depth)

    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    # ── Legacy top-level keys ──
    result['domain'] = root_domain
    result['subdomains'] = []
    result['total_found'] = 0
    result['wordlist_size'] = 0
    result['wildcard_ip'] = None
    result['permutation_count'] = 0

    if not root_domain:
        result['errors'].append('Could not extract root domain from target URL')
        return finalize_result(result, start)

    # ── Step 1: Wildcard baseline detection ──
    wildcard_ip = _detect_wildcard(root_domain)
    result['wildcard_ip'] = wildcard_ip
    if wildcard_ip:
        result['metadata']['wildcard_dns'] = True
        result['metadata']['wildcard_ip'] = wildcard_ip
        result['issues'].append(
            f'Wildcard DNS detected — *.{root_domain} → {wildcard_ip}. '
            f'Results filtered to exclude wildcard matches.'
        )

    # ── Step 2: Load wordlist ──
    wordlist_file = _WORDLIST_MAP.get(depth, _WORDLIST_MAP['medium'])
    prefixes = load_data_lines(wordlist_file)

    # Supplement with SecLists DNS wordlist when available
    if _SECLISTS and _SECLISTS.is_installed:
        sl_entries = _SECLISTS.read_payloads(
            'discovery_dns',
            max_lines=0 if depth == 'deep' else (1000 if depth == 'medium' else 200),
        )
        if sl_entries:
            combined: set[str] = set(prefixes)
            combined.update(sl_entries)
            prefixes = list(combined)
            logger.info('SecLists DNS wordlist added %d entries (total %d)', len(sl_entries), len(prefixes))

    if not prefixes:
        result['errors'].append(f'Wordlist {wordlist_file} is empty or missing')
        return finalize_result(result, start)

    # ── Step 3: Generate permutations (deep scan with known subs) ──
    perm_prefixes: list[str] = []
    if depth == 'deep' and known_subdomains:
        perm_prefixes = _generate_permutations(known_subdomains, root_domain)
        result['permutation_count'] = len(perm_prefixes)

    all_prefixes = list(set(prefixes + perm_prefixes))
    result['wordlist_size'] = len(all_prefixes)
    result['stats']['total_checks'] = len(all_prefixes)

    logger.info(
        'Starting subdomain enumeration for %s with %d prefixes '
        '(%d wordlist + %d permutations, depth=%s)',
        root_domain, len(all_prefixes), len(prefixes),
        len(perm_prefixes), depth,
    )

    # ── Step 4: Parallel resolution ──
    discovered: list[dict] = []
    failed_count = 0

    def _check(prefix: str) -> dict | None:
        fqdn = f'{prefix.strip()}.{root_domain}'
        res = _resolve_subdomain(fqdn)
        # Filter out wildcard matches
        if res and wildcard_ip and res['ip'] == wildcard_ip:
            return None
        return res

    try:
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            future_map = {
                pool.submit(_check, prefix): prefix for prefix in all_prefixes
            }
            for future in as_completed(future_map):
                try:
                    res = future.result()
                    if res is not None:
                        discovered.append(res)
                    else:
                        failed_count += 1
                except Exception as exc:
                    failed_count += 1
                    logger.debug(
                        'Subdomain check error for %s: %s',
                        future_map[future], exc,
                    )
    except Exception as exc:
        result['errors'].append(f'Thread pool error: {exc}')
        logger.error('Subdomain enum thread pool error: %s', exc)

    # ── Sort by name for deterministic output ──
    discovered.sort(key=lambda d: d['name'])

    result['subdomains'] = discovered
    result['total_found'] = len(discovered)
    result['stats']['successful_checks'] = len(discovered)
    result['stats']['failed_checks'] = failed_count

    # Add findings
    for sub in discovered:
        add_finding(result, {
            'type': 'subdomain',
            'name': sub['name'],
            'ip': sub['ip'],
            'source': 'dns_bruteforce',
        })

    # Flag interesting subdomains
    _INTERESTING = {
        'admin', 'staging', 'dev', 'test', 'internal', 'vpn',
        'api', 'debug', 'old', 'backup', 'jenkins', 'git',
        'ci', 'jira', 'grafana', 'kibana', 'elastic', 'mongo',
        'phpmyadmin', 'mysql', 'postgres', 'redis', 'rabbitmq',
    }
    for sub in discovered:
        prefix = sub['name'].replace(f'.{root_domain}', '').split('.')[0]
        if prefix in _INTERESTING:
            result['issues'].append(
                f'Potentially sensitive subdomain discovered: {sub["name"]} ({sub["ip"]})'
            )

    # Detect wildcard DNS (if many IPs are identical) — refinement on top of baseline
    if len(discovered) > 10 and not wildcard_ip:
        ip_counts: dict[str, int] = {}
        for sub in discovered:
            ip_counts[sub['ip']] = ip_counts.get(sub['ip'], 0) + 1
        for ip, count in ip_counts.items():
            ratio = count / len(discovered)
            if ratio > 0.8:
                result['issues'].append(
                    f'Wildcard DNS suspected — {count}/{len(discovered)} '
                    f'subdomains resolve to {ip}'
                )
                result['metadata']['wildcard_dns'] = True
                result['wildcard_ip'] = ip
                break

    # Track permutation vs wordlist hits
    if perm_prefixes:
        perm_set = set(perm_prefixes)
        perm_hits = sum(
            1 for sub in discovered
            if sub['name'].replace(f'.{root_domain}', '').split('.')[0] in perm_set
        )
        result['metadata']['permutation_hits'] = perm_hits
        if perm_hits:
            logger.info('Permutation engine found %d additional subdomains', perm_hits)

    logger.info(
        'Subdomain enumeration complete for %s: %d/%d found',
        root_domain, len(discovered), len(prefixes),
    )

    # ── External tool augmentation (assetfinder / findomain / chaos) ──
    try:
        from apps.scanning.engine.tools.wrappers.assetfinder_wrapper import AssetfinderTool
        from apps.scanning.engine.tools.wrappers.findomain_wrapper import FindomainTool
        from apps.scanning.engine.tools.wrappers.chaos_wrapper import ChaosTool
        _existing_subs = {s['name'] for s in result.get('subdomains', [])}
        for _ToolCls in (AssetfinderTool, FindomainTool, ChaosTool):
            try:
                _ext = _ToolCls()
                if _ext.is_available():
                    for _tr in _ext.run(root_domain):
                        if _tr.host and _tr.host not in _existing_subs:
                            _existing_subs.add(_tr.host)
                            result['subdomains'].append({
                                'name': _tr.host, 'ip': '', 'source': _ext.name,
                            })
            except Exception:
                pass
        result['total_found'] = len(result['subdomains'])
    except Exception:
        pass

    return finalize_result(result, start)
