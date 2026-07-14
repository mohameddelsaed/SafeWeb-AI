"""
Subdomain Brute-Force Module — Advanced subdomain discovery with permutations.

Goes beyond simple wordlist by generating permutations of known subdomains
(dev-api, api-staging, etc.) and testing multi-level subdomains.

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import product

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

_MAX_WORKERS = 20
_RESOLVE_TIMEOUT = 3

# ── Permutation building blocks ───────────────────────────────────────────

COMMON_PREFIXES = [
    'dev', 'staging', 'test', 'qa', 'uat', 'prod', 'internal',
    'admin', 'api', 'v2', 'beta', 'alpha', 'demo', 'sandbox',
    'pre', 'stage', 'lab', 'ci', 'cd', 'build',
]

COMMON_SUFFIXES = [
    '-dev', '-staging', '-test', '-old', '-new', '-backup', '-internal',
    '-prod', '-qa', '-uat', '-v2', '-beta', '-legacy', '-temp',
    '-demo', '-sandbox', '-cache', '-cdn', '-origin',
]

NUMBER_RANGE = range(1, 6)  # 1–5 for number variants


# ── Helpers ────────────────────────────────────────────────────────────────

def _resolve(fqdn: str) -> dict | None:
    """Resolve *fqdn* via :func:`socket.getaddrinfo` and return ``{name, ip}`` or *None*."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_RESOLVE_TIMEOUT)
        results = socket.getaddrinfo(fqdn, None, socket.AF_INET)
        if results:
            ip = results[0][4][0]
            return {'name': fqdn, 'ip': ip}
    except (socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
    return None


def _build_permutations(
    known_subdomains: list[str],
    root_domain: str,
    depth: str = 'medium',
) -> list[str]:
    """Generate candidate FQDNs from known subdomain labels.

    Args:
        known_subdomains: List of already-known subdomain *labels* (e.g. ``['api', 'mail']``).
        root_domain:      Registrable domain.
        depth:            ``'quick'`` | ``'medium'`` | ``'deep'``.

    Returns:
        Deduplicated list of FQDNs to resolve.
    """
    labels = set()
    for sub in known_subdomains:
        # Strip the root domain portion if the caller passed full names
        label = sub.replace(f'.{root_domain}', '').strip('.').split('.')[0]
        if label:
            labels.add(label)

    candidates: set[str] = set()

    # Prefix permutations: prefix-label  (e.g. dev-api)
    for prefix, label in product(COMMON_PREFIXES, labels):
        candidates.add(f'{prefix}-{label}.{root_domain}')

    if depth in ('medium', 'deep'):
        # Suffix permutations: label+suffix  (e.g. api-staging)
        for label, suffix in product(labels, COMMON_SUFFIXES):
            candidates.add(f'{label}{suffix}.{root_domain}')

    if depth == 'deep':
        # Number variants: label1, label2 …
        for label, num in product(labels, NUMBER_RANGE):
            candidates.add(f'{label}{num}.{root_domain}')
        # Multi-level: prefix.label.root
        for prefix, label in product(COMMON_PREFIXES[:10], labels):
            candidates.add(f'{prefix}.{label}.{root_domain}')

    # Also test bare prefixes (useful when known_subdomains is sparse)
    for prefix in COMMON_PREFIXES:
        candidates.add(f'{prefix}.{root_domain}')

    # Remove any FQDN that is just the root domain itself
    candidates.discard(root_domain)
    candidates.discard(f'.{root_domain}')

    return sorted(candidates)


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_subdomain_brute(
    target_url: str,
    known_subdomains: list | None = None,
    depth: str = 'medium',
) -> dict:
    """Advanced subdomain brute-forcing with permutation generation.

    Args:
        target_url:       Target URL to analyse.
        known_subdomains: Previously discovered subdomain names/labels.
        depth:            ``'quick'``, ``'medium'``, or ``'deep'``.

    Returns:
        Standardised result dict with legacy keys:
        ``domain``, ``new_subdomains``, ``permutations_tested``, ``total_found``.
    """
    start = time.time()
    result = create_result('subdomain_brute', target_url, depth)

    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    # Legacy top-level keys
    result['domain'] = root_domain
    result['new_subdomains'] = []
    result['permutations_tested'] = 0
    result['total_found'] = 0

    if not root_domain:
        result['errors'].append('Could not extract root domain from target URL')
        return finalize_result(result, start)

    known = known_subdomains or []
    # If no known subdomains, seed with a small set of common labels
    if not known:
        known = ['www', 'mail', 'api', 'app', 'admin', 'dev', 'staging']

    candidates = _build_permutations(known, root_domain, depth)
    result['permutations_tested'] = len(candidates)
    result['stats']['total_checks'] = len(candidates)

    logger.info(
        'Subdomain brute-force for %s — %d permutations (depth=%s)',
        root_domain, len(candidates), depth,
    )

    # ── Parallel resolution ────────────────────────────────────────────
    discovered: list[dict] = []
    failed = 0

    try:
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {pool.submit(_resolve, fqdn): fqdn for fqdn in candidates}
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res is not None:
                        discovered.append(res)
                    else:
                        failed += 1
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    logger.debug('Resolve error for %s: %s', futures[future], exc)
    except Exception as exc:
        result['errors'].append(f'Thread pool error: {exc}')
        logger.error('Subdomain brute thread pool error: %s', exc)

    discovered.sort(key=lambda d: d['name'])

    result['new_subdomains'] = discovered
    result['total_found'] = len(discovered)
    result['stats']['successful_checks'] = len(discovered)
    result['stats']['failed_checks'] = failed

    # ── Findings ───────────────────────────────────────────────────────
    for sub in discovered:
        add_finding(result, {
            'type': 'subdomain_brute',
            'name': sub['name'],
            'ip': sub['ip'],
            'source': 'permutation_bruteforce',
        })

    # Flag sensitive patterns
    _SENSITIVE_KEYWORDS = {
        'admin', 'internal', 'staging', 'dev', 'test', 'backup',
        'debug', 'old', 'legacy', 'temp', 'vpn', 'jenkins', 'git',
    }
    for sub in discovered:
        prefix = sub['name'].replace(f'.{root_domain}', '').lower()
        for keyword in _SENSITIVE_KEYWORDS:
            if keyword in prefix:
                result['issues'].append(
                    f'Sensitive permutation resolved: {sub["name"]} ({sub["ip"]})'
                )
                break

    # Wildcard detection
    if len(discovered) > 20:
        ip_counts: dict[str, int] = {}
        for sub in discovered:
            ip_counts[sub['ip']] = ip_counts.get(sub['ip'], 0) + 1
        for ip, count in ip_counts.items():
            if count / len(discovered) > 0.8:
                result['issues'].append(
                    f'Wildcard DNS likely — {count}/{len(discovered)} '
                    f'permutations resolve to {ip}'
                )
                result['metadata']['wildcard_dns'] = True
                break

    logger.info(
        'Subdomain brute-force complete for %s: %d found / %d tested',
        root_domain, len(discovered), len(candidates),
    )
    return finalize_result(result, start)
