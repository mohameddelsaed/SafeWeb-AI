"""
Email Enumeration Module — Discover email addresses associated with domain.

Harvests from HTML content, DNS records (SOA/TXT), WHOIS data,
PGP key servers, certificate transparency logs, and common email patterns.
Modelled after theHarvester and Hunter.io discovery methodology.

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time
import urllib.request
import urllib.parse
import json

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# RFC-5322–ish email regex (intentionally broad for harvesting)
_EMAIL_RE = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
)

# Common role-based addresses to generate as candidates
_COMMON_ROLES = [
    'info', 'admin', 'support', 'security', 'webmaster',
    'contact', 'abuse', 'postmaster', 'sales', 'noreply',
    'help', 'billing', 'team', 'hr', 'careers',
]

# Disposable / noise domains to filter out
_NOISE_DOMAINS = {
    'example.com', 'example.org', 'example.net',
    'sentry.io', 'wixpress.com', 'w3.org',
    'schema.org', 'cloudflare.com', 'googleapis.com',
    'jquery.com', 'gravatar.com', 'wordpress.org',
}


# ── Extractors ─────────────────────────────────────────────────────────────

def _extract_from_html(body: str, root_domain: str) -> list[dict]:
    """Harvest emails from HTML / page content."""
    results: list[dict] = []
    if not body:
        return results
    for match in _EMAIL_RE.finditer(body):
        email = match.group(0).lower().rstrip('.')
        domain = email.split('@')[1] if '@' in email else ''
        if domain in _NOISE_DOMAINS:
            continue
        confidence = 'high' if root_domain in domain else 'medium'
        results.append({
            'address': email,
            'source': 'html_content',
            'confidence': confidence,
        })
    return results


def _extract_from_dns(dns_results: dict | None, root_domain: str) -> list[dict]:
    """Pull emails from SOA contact and TXT records (SPF includes, etc.)."""
    results: list[dict] = []
    if not dns_results:
        return results

    # SOA rname field often encodes an email (hostmaster.example.com → hostmaster@example.com)
    soa = dns_results.get('records', {}).get('soa')
    if isinstance(soa, dict):
        rname = soa.get('rname', '') or soa.get('email', '')
        if rname:
            # SOA uses first dot as @, rest remain dots
            parts = rname.split('.')
            if len(parts) >= 3:
                email = f'{parts[0]}@{".".join(parts[1:])}'.lower()
                if _EMAIL_RE.fullmatch(email):
                    results.append({
                        'address': email,
                        'source': 'dns_soa',
                        'confidence': 'high',
                    })
    elif isinstance(soa, str) and '@' in soa:
        for m in _EMAIL_RE.finditer(soa):
            results.append({
                'address': m.group(0).lower(),
                'source': 'dns_soa',
                'confidence': 'high',
            })

    # TXT records
    txt_records = dns_results.get('records', {}).get('txt', [])
    for rec in txt_records:
        text = rec if isinstance(rec, str) else str(rec)
        for m in _EMAIL_RE.finditer(text):
            email = m.group(0).lower()
            if email.split('@')[1] not in _NOISE_DOMAINS:
                results.append({
                    'address': email,
                    'source': 'dns_txt',
                    'confidence': 'high',
                })

    return results


def _extract_from_whois(whois_results: dict | None) -> list[dict]:
    """Pull emails from WHOIS data."""
    results: list[dict] = []
    if not whois_results:
        return results

    # Scan common WHOIS fields
    for key in ('registrant_email', 'admin_email', 'tech_email',
                'abuse_email', 'emails', 'registrant_contact', 'admin_contact'):
        value = whois_results.get(key)
        if not value:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, str):
                for m in _EMAIL_RE.finditer(item):
                    results.append({
                        'address': m.group(0).lower(),
                        'source': 'whois',
                        'confidence': 'high',
                    })

    # Also search the raw WHOIS text if present
    raw = whois_results.get('raw', '') or whois_results.get('raw_text', '')
    if raw:
        for m in _EMAIL_RE.finditer(raw):
            email = m.group(0).lower()
            if email.split('@')[1] not in _NOISE_DOMAINS:
                results.append({
                    'address': email,
                    'source': 'whois',
                    'confidence': 'medium',
                })

    return results


def _generate_common_emails(root_domain: str) -> list[dict]:
    """Generate common role-based email candidates."""
    return [
        {
            'address': f'{role}@{root_domain}',
            'source': 'common_pattern',
            'confidence': 'low',
        }
        for role in _COMMON_ROLES
    ]


def _query_pgp_keyserver(root_domain: str) -> list[dict]:
    """Search OpenPGP key server for email addresses with the target domain.

    Queries ``https://keys.openpgp.org/vks/v1/search?q=@domain.com``
    which is a public REST API requiring no authentication.
    """
    results: list[dict] = []
    try:
        encoded = urllib.parse.quote(f'@{root_domain}')
        url = f'https://keys.openpgp.org/vks/v1/search?q={encoded}'
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'SafeWeb-AI-Recon/1.0', 'Accept': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(32768).decode('utf-8', errors='replace')

        # Response contains "Mailer-IDs" list or HTML with key details
        # Extract all email-like strings
        for m in _EMAIL_RE.finditer(body):
            email = m.group(0).lower()
            if root_domain in email and email.split('@')[1] not in _NOISE_DOMAINS:
                results.append({
                    'address': email,
                    'source': 'pgp_keyserver',
                    'confidence': 'high',
                })
    except Exception as exc:
        logger.debug('PGP keyserver query failed for %s: %s', root_domain, exc)
    return results


def _query_pgp_mit(root_domain: str) -> list[dict]:
    """Fallback PGP query against MIT HKP keyserver (key search endpoint)."""
    results: list[dict] = []
    try:
        encoded = urllib.parse.quote(f'@{root_domain}')
        url = f'https://pgp.mit.edu/pks/lookup?search={encoded}&op=index'
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'SafeWeb-AI-Recon/1.0'},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(65536).decode('utf-8', errors='replace')

        for m in _EMAIL_RE.finditer(body):
            email = m.group(0).lower()
            if root_domain in email and email.split('@')[1] not in _NOISE_DOMAINS:
                results.append({
                    'address': email,
                    'source': 'pgp_mit',
                    'confidence': 'high',
                })
    except Exception as exc:
        logger.debug('MIT PGP keyserver query failed for %s: %s', root_domain, exc)
    return results


def _query_crt_emails(root_domain: str) -> list[dict]:
    """Extract email addresses embedded in certificate Subject fields via crt.sh.

    Some certificates include email addresses in the Subject DN or SANs.
    Queries ``https://crt.sh/?q=%40domain.com&output=json`` to find them.
    """
    results: list[dict] = []
    try:
        encoded = urllib.parse.quote(f'@{root_domain}')
        url = f'https://crt.sh/?q={encoded}&output=json'
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'SafeWeb-AI-Recon/1.0'},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(65536).decode('utf-8', errors='replace')

        try:
            entries = json.loads(body)
            for entry in (entries if isinstance(entries, list) else []):
                for field in ('common_name', 'name_value', 'issuer_name'):
                    text = entry.get(field, '') or ''
                    for m in _EMAIL_RE.finditer(text):
                        email = m.group(0).lower()
                        if root_domain in email:
                            results.append({
                                'address': email,
                                'source': 'crt_sh',
                                'confidence': 'high',
                            })
        except (json.JSONDecodeError, TypeError):
            # Fallback: regex against raw response
            for m in _EMAIL_RE.finditer(body):
                email = m.group(0).lower()
                if root_domain in email:
                    results.append({
                        'address': email,
                        'source': 'crt_sh',
                        'confidence': 'medium',
                    })
    except Exception as exc:
        logger.debug('crt.sh email query failed for %s: %s', root_domain, exc)
    return results


def _detect_email_format(emails: list[dict], root_domain: str) -> list[dict]:
    """Detect email naming convention and generate format-based candidates.

    If we discover 'john.doe@target.com' we can infer the company uses
    'first.last' format and generate candidates for other employees.
    Returns generated candidates with confidence='low'.
    """
    candidates: list[dict] = []
    real_emails = [
        e['address'] for e in emails
        if root_domain in e['address'] and e['confidence'] in ('high', 'medium')
    ]
    if len(real_emails) < 2:
        return candidates

    has_dot = sum(1 for e in real_emails if '.' in e.split('@')[0])
    has_underscore = sum(1 for e in real_emails if '_' in e.split('@')[0])

    # If dot-separated names dominate, generate first.last candidates
    if has_dot > len(real_emails) * 0.4:
        sample_names = [
            'john.smith', 'jane.doe', 'michael.brown',
            'sarah.jones', 'david.wilson', 'emily.taylor',
        ]
        for name in sample_names:
            candidates.append({
                'address': f'{name}@{root_domain}',
                'source': 'format_inference',
                'confidence': 'low',
            })
    elif has_underscore > len(real_emails) * 0.4:
        sample_names = [
            'john_smith', 'jane_doe', 'michael_brown',
        ]
        for name in sample_names:
            candidates.append({
                'address': f'{name}@{root_domain}',
                'source': 'format_inference',
                'confidence': 'low',
            })

    return candidates


def _analyse_patterns(emails: list[dict], root_domain: str) -> list[str]:
    """Detect naming patterns from discovered addresses."""
    patterns: list[str] = []
    local_parts = [
        e['address'].split('@')[0]
        for e in emails
        if root_domain in e['address'] and e['confidence'] != 'low'
    ]
    if not local_parts:
        return patterns

    # Detect first.last vs firstlast vs f.last etc.
    dot_count = sum(1 for lp in local_parts if '.' in lp)
    if dot_count > len(local_parts) * 0.5:
        patterns.append('first.last')
    underscore_count = sum(1 for lp in local_parts if '_' in lp)
    if underscore_count > len(local_parts) * 0.3:
        patterns.append('first_last')
    short_count = sum(1 for lp in local_parts if len(lp) <= 3)
    if short_count > len(local_parts) * 0.3:
        patterns.append('initials')

    return patterns


def _deduplicate(emails: list[dict]) -> list[dict]:
    """Remove duplicate addresses, keeping the highest-confidence entry."""
    _PRIO = {'high': 0, 'medium': 1, 'low': 2}
    best: dict[str, dict] = {}
    for entry in emails:
        addr = entry['address']
        if addr not in best or _PRIO.get(entry['confidence'], 3) < _PRIO.get(best[addr]['confidence'], 3):
            best[addr] = entry
    return sorted(best.values(), key=lambda e: e['address'])


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_email_enum(
    target_url: str,
    response_body: str = '',
    dns_results: dict | None = None,
    whois_results: dict | None = None,
    depth: str = 'medium',
) -> dict:
    """Enumerate email addresses associated with the target domain.

    Sources:
    - HTML content of the target page
    - DNS records (SOA rname, TXT)
    - WHOIS data
    - PGP key servers (keys.openpgp.org, pgp.mit.edu)
    - Certificate Transparency via crt.sh
    - Common role-based pattern generation
    - Email format inference from discovered addresses

    Args:
        target_url:    Target URL.
        response_body: HTML body of the target page (optional).
        dns_results:   Dict from ``run_dns_recon`` (optional).
        whois_results: Dict from ``run_whois_recon`` (optional).
        depth:         'shallow' (HTML+DNS+WHOIS only), 'medium' (+ PGP),
                       'deep' (+ crt.sh + format inference).

    Returns:
        Standardised result dict with legacy keys:
        ``emails``, ``patterns``, ``domain``, ``total_found``, ``issues``.
    """
    start = time.time()
    result = create_result('email_enum', target_url)

    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    # Legacy top-level keys
    result['emails'] = []
    result['patterns'] = []
    result['domain'] = root_domain
    result['total_found'] = 0

    if not root_domain:
        result['errors'].append('Could not extract root domain from target URL')
        return finalize_result(result, start)

    logger.info('Starting email enumeration for %s', root_domain)

    all_emails: list[dict] = []
    checks = 0

    # 1. HTML content extraction
    checks += 1
    try:
        html_emails = _extract_from_html(response_body, root_domain)
        all_emails.extend(html_emails)
        result['stats']['successful_checks'] += 1
        logger.debug('Extracted %d emails from HTML', len(html_emails))
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'HTML extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 2. DNS record extraction
    checks += 1
    try:
        dns_emails = _extract_from_dns(dns_results, root_domain)
        all_emails.extend(dns_emails)
        result['stats']['successful_checks'] += 1
        logger.debug('Extracted %d emails from DNS', len(dns_emails))
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'DNS extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 3. WHOIS extraction
    checks += 1
    try:
        whois_emails = _extract_from_whois(whois_results)
        all_emails.extend(whois_emails)
        result['stats']['successful_checks'] += 1
        logger.debug('Extracted %d emails from WHOIS', len(whois_emails))
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'WHOIS extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 4. Common pattern generation
    checks += 1
    common = _generate_common_emails(root_domain)
    all_emails.extend(common)
    result['stats']['successful_checks'] += 1

    # 5. PGP key server search (medium/deep)
    if depth in ('medium', 'deep'):
        checks += 1
        try:
            pgp_emails = _query_pgp_keyserver(root_domain)
            all_emails.extend(pgp_emails)
            result['stats']['successful_checks'] += 1
            logger.debug('Extracted %d emails from PGP keyserver', len(pgp_emails))
        except Exception as exc:  # noqa: BLE001
            result['errors'].append(f'PGP keyserver error: {exc}')
            result['stats']['failed_checks'] += 1

        # Fallback PGP source
        checks += 1
        try:
            pgp_mit = _query_pgp_mit(root_domain)
            all_emails.extend(pgp_mit)
            result['stats']['successful_checks'] += 1
            logger.debug('Extracted %d emails from MIT PGP keyserver', len(pgp_mit))
        except Exception:  # noqa: BLE001
            result['stats']['failed_checks'] += 1

    # 6. Certificate Transparency email search (deep)
    if depth == 'deep':
        checks += 1
        try:
            crt_emails = _query_crt_emails(root_domain)
            all_emails.extend(crt_emails)
            result['stats']['successful_checks'] += 1
            logger.debug('Extracted %d emails from crt.sh', len(crt_emails))
        except Exception as exc:  # noqa: BLE001
            result['errors'].append(f'crt.sh error: {exc}')
            result['stats']['failed_checks'] += 1

    result['stats']['total_checks'] = checks

    # Deduplicate and analyse
    unique = _deduplicate(all_emails)
    patterns = _analyse_patterns(unique, root_domain)

    # 7. Format-based inference (deep — after deduplication)
    if depth == 'deep':
        inferred = _detect_email_format(unique, root_domain)
        unique = _deduplicate(unique + inferred)

    result['emails'] = unique
    result['patterns'] = patterns
    result['total_found'] = len(unique)

    # Populate findings
    for entry in unique:
        add_finding(result, {
            'type': 'email',
            'address': entry['address'],
            'source': entry['source'],
            'confidence': entry['confidence'],
        })

    # Security observations
    domain_emails = [e for e in unique if root_domain in e['address'] and e['confidence'] != 'low']
    if len(domain_emails) > 5:
        result['issues'].append(
            f'{len(domain_emails)} email addresses discovered — potential target for phishing'
        )
    role_exposed = [e for e in unique if e['source'] != 'common_pattern'
                    and e['address'].split('@')[0] in {'admin', 'root', 'security'}]
    if role_exposed:
        result['issues'].append(
            'Sensitive role-based email(s) exposed: '
            + ', '.join(e['address'] for e in role_exposed)
        )

    logger.info('Email enumeration complete for %s: %d found', root_domain, len(unique))
    return finalize_result(result, start)
