"""
Subdomain Permutation Engine — AlterX / dnsgen-style permutation generator.

Replicates the core permutation logic of:
  • AlterX  (projectdiscovery/alterx) — word extraction + template engine
  • dnsgen  (ProjectAnte/dnsgen)      — word-based permutations
  • altdns  (infosec-au/altdns)       — prefix/suffix mutations

Generates candidate subdomains by combining:
  - Known subdomain labels with common environment/role prefixes & suffixes
  - Number increments and decrements of existing labels
  - Word-swap permutations (api-v1 → api-v2, api-v3 …)
  - Cross-product of high-value wordlist + known labels
"""
import re
import itertools
import logging
from datetime import datetime
import time
from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# ── Environment / role prefixes (from AlterX built-in wordlist) ───────────
_PREFIXES = [
    'dev', 'stg', 'staging', 'prod', 'production', 'test', 'qa', 'uat',
    'beta', 'alpha', 'preview', 'demo', 'internal', 'ext', 'external',
    'old', 'new', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6',
    'api', 'api2', 'api3', 'rest', 'graphql', 'rpc',
    'app', 'apps', 'app2', 'portal', 'dashboard', 'admin',
    'cdn', 'static', 'assets', 'media', 'files', 'img', 'images',
    'mail', 'smtp', 'pop', 'imap', 'email', 'webmail', 'mx',
    'vpn', 'ssh', 'ftp', 'sftp', 'ftps', 'git', 'svn',
    'jenkins', 'ci', 'cd', 'build', 'deploy',
    'db', 'database', 'mysql', 'redis', 'mongo', 'postgres', 'elastic',
    'auth', 'login', 'sso', 'oauth', 'accounts', 'id',
    'monitoring', 'metrics', 'grafana', 'kibana', 'logs', 'log',
    'corp', 'intranet', 'hr', 'finance', 'legal',
    'us', 'eu', 'asia', 'us-east', 'us-west', 'eu-west', 'ap',
]

# ── Suffixes ──────────────────────────────────────────────────────────────
_SUFFIXES = [
    '-dev', '-stg', '-staging', '-prod', '-test', '-qa', '-uat',
    '-beta', '-internal', '-ext', '-old', '-new', '-v2', '-v3',
    '-api', '-app', '-admin', '-portal', '-auth',
    '-backup', '-bak', '-archive', '-tmp', '-temp',
    '2', '3', '1', '-1', '-2',
    '-us', '-eu', '-asia',
]

# ── Number patterns to increment/decrement ────────────────────────────────
_NUM_RE = re.compile(r'(\d+)')

# ── AlterX-style word extraction pattern ─────────────────────────────────
_WORD_EXTRACT_RE = re.compile(r'[a-z0-9]+')


def _extract_words(label: str) -> list[str]:
    """Split a subdomain label into constituent words (api-v1 → [api, v1])."""
    return _WORD_EXTRACT_RE.findall(label.lower())


def _increment_numbers(label: str, steps: int = 3) -> list[str]:
    """
    Replace numbers in *label* with incremented/decremented variants.
    E.g. api-v1 → api-v2, api-v3, api-v4, api-v0
    """
    variants = []
    match = _NUM_RE.search(label)
    if match:
        num = int(match.group(1))
        for delta in range(1, steps + 1):
            for n in [num + delta, num - delta]:
                if n >= 0:
                    new = _NUM_RE.sub(str(n), label, count=1)
                    if new not in variants:
                        variants.append(new)
    return variants


def _apply_prefix(prefix: str, label: str) -> list[str]:
    """Generate prefix-label and prefix.label forms."""
    return [f'{prefix}-{label}', f'{prefix}.{label}']


def _apply_suffix(label: str, suffix: str) -> list[str]:
    """Generate label-suffix and label+suffix forms."""
    new = f'{label}{suffix}'
    return [new] if new != label else []


def run_subdomain_permutation(
    domain: str,
    known_subdomains: list[str] | None = None,
    depth: str = 'medium',
    max_permutations: int = 0,
) -> dict:
    """
    Generate subdomain permutations for active DNS brute-forcing.

    Args:
        domain:           Root domain (e.g. ``example.com``).
        known_subdomains: List of already-known subdomains to permute.
                          Can include FQDNs or bare labels.
        depth:            Controls generation breadth:
                            shallow → prefixes only;
                            medium  → prefixes + suffixes + numbers;
                            deep    → all + cross-product;
        max_permutations: Hard cap on output size (0 = no cap).

    Returns:
        Standardised result dict with extra key:
            ``permutations``: list[str] — unique candidate subdomains
    """
    start = time.time()
    result = create_result('subdomain_permutation', domain)
    result['permutations'] = []

    if not known_subdomains:
        known_subdomains = []

    # Normalise inputs — strip domain suffix, keep unique labels
    labels: list[str] = []
    seen_labels: set[str] = set()
    for sub in known_subdomains:
        # Strip trailing dot and domain suffix
        bare = sub.lower().rstrip('.')
        if bare.endswith('.' + domain.lower()):
            bare = bare[: -(len(domain) + 1)]
        if bare and bare not in seen_labels:
            labels.append(bare)
            seen_labels.add(bare)

    if not labels:
        # Seed with a minimal set when nothing is known
        labels = ['www', 'api', 'app', 'mail', 'dev']

    candidates: set[str] = set()

    # ── Phase 1: Prefix permutations ─────────────────────────────────────
    for label in labels:
        for pfx in _PREFIXES:
            if pfx != label:
                for form in _apply_prefix(pfx, label):
                    candidates.add(f'{form}.{domain}')

    # ── Phase 2: Suffix permutations ─────────────────────────────────────
    if depth in ('medium', 'deep'):
        for label in labels:
            for sfx in _SUFFIXES:
                for form in _apply_suffix(label, sfx):
                    candidates.add(f'{form}.{domain}')

    # ── Phase 3: Number increments ────────────────────────────────────────
    if depth in ('medium', 'deep'):
        for label in labels:
            for new_label in _increment_numbers(label):
                candidates.add(f'{new_label}.{domain}')

    # ── Phase 4: Word-level cross-product (deep only) ─────────────────────
    if depth == 'deep':
        # Extract unique words from all known labels
        all_words: set[str] = set()
        for label in labels:
            all_words.update(_extract_words(label))

        # Pair each word with high-value prefixes
        for word, pfx in itertools.product(all_words, _PREFIXES[:20]):
            for form in _apply_prefix(pfx, word):
                candidates.add(f'{form}.{domain}')

        # Direct wordlist anchoring: prefix+domain directly
        for pfx in _PREFIXES:
            candidates.add(f'{pfx}.{domain}')
        for sfx in ['2', '-backup', '-old', '-v2']:
            for label in labels[:30]:
                candidates.add(f'{label}{sfx}.{domain}')

    # Remove known subdomains (already discovered)
    known_fqdns = {f'{lbl}.{domain}' for lbl in labels}
    candidates -= known_fqdns

    # Apply cap
    ordered = sorted(candidates)
    if max_permutations and len(ordered) > max_permutations:
        ordered = ordered[:max_permutations]

    result['permutations'] = ordered

    result['stats']['total_checks'] = len(labels)
    result['stats']['successful_checks'] = len(ordered)

    add_finding(result, {
        'type': 'permutations_generated',
        'domain': domain,
        'known_labels': len(labels),
        'permutations_generated': len(ordered),
        'depth': depth,
        'description': (
            f'Generated {len(ordered)} subdomain permutations for {domain} '
            f'from {len(labels)} known labels at depth={depth}.'
        ),
        'severity': 'info',
    })

    logger.info(
        'Subdomain permutation: %d candidates generated for %s (depth=%s)',
        len(ordered), domain, depth,
    )

    result['metadata']['completed_at'] = datetime.utcnow().isoformat()
    return finalize_result(result, start)
