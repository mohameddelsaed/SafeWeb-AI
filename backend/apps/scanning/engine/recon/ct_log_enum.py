"""
CT Log Enumeration Module — Certificate Transparency subdomain discovery.

Queries multiple CT log sources to enumerate subdomains:
  - crt.sh (primary, no auth required)
  - Certspotter (sslmate.com public API, no auth for limited queries)

Supports depth levels: quick (skip), medium (crt.sh only), deep (all sources).

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# API base URLs
_CRT_SH_URL = 'https://crt.sh/'
_CERTSPOTTER_URL = 'https://api.certspotter.com/v1/issuances'

# Timeout for HTTP requests (seconds)
_REQUEST_TIMEOUT = 15

# Subdomains whose prefixes suggest a sensitive/interesting target
_INTERESTING_PREFIXES = frozenset([
    'admin', 'administrator', 'staging', 'stage', 'stg',
    'dev', 'development', 'test', 'testing', 'qa', 'uat',
    'internal', 'intranet', 'vpn', 'remote', 'portal',
    'api', 'api-dev', 'api-staging', 'api-test', 'api-internal',
    'debug', 'debugger', 'old', 'legacy', 'backup',
    'jenkins', 'ci', 'cd', 'cicd', 'build', 'deploy',
    'git', 'gitlab', 'github', 'bitbucket', 'svn',
    'jira', 'confluence', 'wiki', 'docs', 'documentation',
    'grafana', 'kibana', 'elastic', 'elasticsearch', 'logstash',
    'mongo', 'mongodb', 'redis', 'postgres', 'mysql', 'db', 'database',
    'k8s', 'kubernetes', 'rancher', 'docker', 'registry',
    'mail', 'smtp', 'imap', 'email', 'webmail', 'mx',
    'ftp', 'sftp', 'ssh', 'rdp',
    'secret', 'private', 'dev-ops', 'devops', 'ops',
    'status', 'monitor', 'monitoring', 'metrics', 'prometheus',
    'vault', 'keycloak', 'auth', 'sso', 'login', 'oauth',
    'chat', 'slack', 'teams',
    'sandbox', 'demo', 'preview', 'beta', 'alpha',
])


# ── Helpers ────────────────────────────────────────────────────────────────

def _query_crtsh(domain: str, wildcard: bool = False) -> list[dict]:
    """Query crt.sh JSON API and return raw certificate entries.

    Args:
        domain:   Root domain to search for (e.g. ``example.com``).
        wildcard: If *True*, search for ``%25.{domain}`` (double-encoded
                  wildcard for nested sub-subdomains).

    Returns:
        List of dicts from the crt.sh JSON response, or empty list on error.
    """
    try:
        import requests  # type: ignore[import-untyped]
    except ImportError:
        logger.warning('requests library not available — cannot query crt.sh')
        return []

    query = f'%.{domain}' if not wildcard else f'%25.{domain}'
    params = {'q': query, 'output': 'json'}

    try:
        resp = requests.get(_CRT_SH_URL, params=params, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        return []
    except requests.exceptions.Timeout:
        logger.warning('crt.sh request timed out for %s', domain)
        return []
    except requests.exceptions.ConnectionError:
        logger.warning('crt.sh connection error for %s', domain)
        return []
    except requests.exceptions.HTTPError as exc:
        logger.warning('crt.sh HTTP error for %s: %s', domain, exc)
        return []
    except (ValueError, TypeError) as exc:
        logger.warning('Failed to parse crt.sh JSON for %s: %s', domain, exc)
        return []


def _extract_subdomains(entries: list[dict], root_domain: str) -> set[str]:
    """Extract unique, valid subdomain names from crt.sh entries.

    The ``name_value`` field may contain multiple names separated by
    newlines and may include wildcard prefixes (``*.``).
    """
    subdomains: set[str] = set()
    root_lower = root_domain.lower()

    for entry in entries:
        name_value = entry.get('name_value', '')
        if not name_value:
            continue
        for name in name_value.split('\n'):
            name = name.strip().lower()
            # Strip wildcard prefix
            if name.startswith('*.'):
                name = name[2:]
            # Must belong to the target root domain
            if not name.endswith(root_lower):
                continue
            # Basic sanity check
            if re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', name):
                subdomains.add(name)

    return subdomains


def _query_certspotter(domain: str) -> set[str]:
    """Query the Certspotter public API for certificate DNS names.

    Endpoint: https://api.certspotter.com/v1/issuances?domain=<domain>
                 &include_subdomains=true&expand=dns_names

    No authentication required for the public unauthenticated tier
    (rate-limited to 100 queries/hour).

    Returns a set of valid subdomain strings for *domain*.
    """
    try:
        import requests  # type: ignore[import-untyped]
    except ImportError:
        return set()

    params = {
        'domain': domain,
        'include_subdomains': 'true',
        'expand': 'dns_names',
    }

    try:
        resp = requests.get(
            _CERTSPOTTER_URL,
            params=params,
            timeout=_REQUEST_TIMEOUT,
            headers={'User-Agent': 'SafeWeb-AI/1.0 (security assessment)'},
        )
        if resp.status_code == 429:
            logger.warning('Certspotter rate limit hit for %s', domain)
            return set()
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.debug('Certspotter query failed for %s: %s', domain, exc)
        return set()

    subdomains: set[str] = set()
    root_lower = domain.lower()

    if not isinstance(data, list):
        return subdomains

    for issuance in data:
        dns_names = issuance.get('dns_names', [])
        if not isinstance(dns_names, list):
            continue
        for name in dns_names:
            name = name.strip().lower()
            if name.startswith('*.'):
                name = name[2:]
            if name.endswith(root_lower) and re.match(
                r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', name
            ):
                subdomains.add(name)

    return subdomains


def _extract_cert_metadata(entries: list[dict]) -> list[dict]:
    """Extract issuer/expiry metadata from crt.sh cert entries.

    Returns a small list of unique issuers seen (useful for threat intel).
    """
    issuers: dict[str, int] = {}
    for entry in entries:
        issuer = entry.get('issuer_name', '')
        if issuer:
            issuers[issuer] = issuers.get(issuer, 0) + 1

    return [{'issuer': k, 'cert_count': v} for k, v in
            sorted(issuers.items(), key=lambda x: x[1], reverse=True)[:10]]


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_ct_log_enum(target_url: str, depth: str = 'medium') -> dict:
    """Enumerate subdomains via Certificate Transparency logs.

    Args:
        target_url: The target URL to analyse.
        depth:      Scan depth — ``'quick'``, ``'medium'``, or ``'deep'``.

    Returns:
        Standardised result dict with legacy keys:
        ``domain``, ``subdomains``, ``total_found``.
    """
    start = time.time()
    result = create_result('ct_log_enum', target_url, depth)

    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    # ── Legacy top-level keys ──
    result['domain'] = root_domain
    result['subdomains'] = []
    result['total_found'] = 0

    if not root_domain:
        result['errors'].append('Could not extract root domain from target URL')
        return finalize_result(result, start)

    # Quick depth: skip CT log enumeration entirely
    if depth == 'quick':
        logger.info('CT log enum skipped (depth=quick) for %s', root_domain)
        result['metadata']['skipped'] = True
        return finalize_result(result, start)

    # ── Medium: basic query ──
    logger.info('Querying crt.sh for %s (depth=%s)', root_domain, depth)
    result['stats']['total_checks'] += 1

    entries = _query_crtsh(root_domain)
    all_subdomains = _extract_subdomains(entries, root_domain)

    if entries:
        result['stats']['successful_checks'] += 1
    else:
        result['stats']['failed_checks'] += 1
        if not entries and depth != 'deep':
            result['errors'].append('crt.sh returned no results or was unreachable')

    # ── Deep: also try double-wildcard query + Certspotter ──
    if depth == 'deep':
        result['stats']['total_checks'] += 1
        logger.info('Running deep wildcard query for %s', root_domain)

        wildcard_entries = _query_crtsh(root_domain, wildcard=True)
        deep_subs = _extract_subdomains(wildcard_entries, root_domain)
        all_subdomains |= deep_subs

        if wildcard_entries:
            result['stats']['successful_checks'] += 1
        else:
            result['stats']['failed_checks'] += 1

        # Query Certspotter as a second independent CT source
        logger.info('Querying Certspotter for %s', root_domain)
        result['stats']['total_checks'] += 1
        certspotter_subs = _query_certspotter(root_domain)
        if certspotter_subs:
            result['stats']['successful_checks'] += 1
            new_from_certspotter = certspotter_subs - all_subdomains
            if new_from_certspotter:
                result['metadata']['certspotter_unique'] = len(new_from_certspotter)
            all_subdomains |= certspotter_subs
        else:
            result['stats']['failed_checks'] += 1

        # Store cert issuer metadata
        all_entries = entries + (wildcard_entries or [])
        cert_meta = _extract_cert_metadata(all_entries)
        if cert_meta:
            result['metadata']['cert_issuers'] = cert_meta

    # ── Build results ──
    sorted_subs = sorted(all_subdomains)
    result['subdomains'] = sorted_subs
    result['total_found'] = len(sorted_subs)

    # Add a finding for each discovered subdomain
    for sub in sorted_subs:
        # Determine depth level from the root
        label_count = sub.replace(root_domain, '').strip('.').count('.') + 1 if sub != root_domain else 0
        add_finding(result, {
            'type': 'ct_subdomain',
            'subdomain': sub,
            'source': 'crt.sh',
            'depth_level': label_count,
        })

    # Flag noteworthy subdomains
    for sub in sorted_subs:
        prefix = sub.replace(f'.{root_domain}', '').split('.')[0]
        if prefix in _INTERESTING_PREFIXES:
            result['issues'].append(
                f'Potentially sensitive subdomain found in CT logs: {sub}'
            )

    logger.info(
        'CT log enum complete for %s: %d subdomains found',
        root_domain, len(sorted_subs),
    )
    return finalize_result(result, start)


# ── Organization-based CT search (for wide scope resolution) ─────────────

def search_by_org(org_name: str) -> list[str]:
    """Search CT logs for certificates issued to an organization name.

    Queries crt.sh with the organization parameter to find domains
    associated with a company. Used by ScopeResolver for wide-scope scans.

    Returns:
        Deduplicated list of domain names (without scheme).
    """
    if not org_name or not org_name.strip():
        return []

    try:
        import requests
    except ImportError:
        logger.warning('requests library not available — cannot query crt.sh')
        return []

    domains: set[str] = set()

    # crt.sh supports searching by organization name
    try:
        params = {'O': org_name, 'output': 'json'}
        resp = requests.get(_CRT_SH_URL, params=params, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        if not isinstance(data, list):
            return []

        for entry in data:
            name_value = entry.get('name_value', '')
            for name in name_value.split('\n'):
                name = name.strip().lower()
                if name.startswith('*.'):
                    name = name[2:]
                # Basic domain validation
                if '.' in name and not name.startswith('.') and len(name) < 253:
                    # Filter out obvious non-domains
                    if all(c.isalnum() or c in '.-' for c in name):
                        domains.add(name)

    except Exception as exc:
        logger.warning('crt.sh org search failed for %s: %s', org_name, exc)

    logger.info('CT org search for "%s" found %d domains', org_name, len(domains))
    return sorted(domains)

