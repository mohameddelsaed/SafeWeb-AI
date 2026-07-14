"""
Threat Intelligence Module — Enrich findings with threat context.
Correlates discovered technologies, IPs, and domains against
known threat patterns, abuse indicators, and reputation data.
"""
import logging
import math
import re
import time
from typing import Optional

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Suspicious TLDs (commonly abused free / cheap TLDs) ───────────────────

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',       # Freenom free TLDs
    '.top', '.xyz', '.buzz', '.icu', '.club',  # Cheap TLDs often abused
    '.work', '.cam', '.surf', '.rest', '.fit',
}

# ── Phishing keyword patterns ─────────────────────────────────────────────

PHISHING_KEYWORDS = [
    r'paypal', r'apple.*id', r'microsoft.*login', r'google.*verify',
    r'bank.*secure', r'account.*verify', r'signin.*update',
    r'secure.*login', r'confirm.*identity', r'suspend.*account',
    r'wallet.*connect', r'crypto.*claim', r'airdrop.*free',
    r'nft.*mint', r'metamask', r'blockchain.*verify',
    r'amazon.*order', r'netflix.*renew', r'facebook.*security',
]

# ── Known suspicious IP ranges (simplified — CIDR-like first octets) ───────

_SUSPICIOUS_IP_PREFIXES = [
    # Commonly abused hosting prefixes (illustrative, not exhaustive)
    '185.220.',  # Known Tor exit / abuse
    '45.33.',    # Budget VPS abuse
    '192.42.',   # Tor exit
    '104.244.',  # Micfo
    '23.129.',   # Tor Project
]

_CLOUD_IP_PREFIXES = [
    '13.', '20.', '40.', '52.', '104.',  # Azure
    '3.', '18.', '34.', '35.', '54.',     # AWS
    '34.', '35.', '130.', '142.',          # GCP
]

# ── Cryptominer JS patterns ───────────────────────────────────────────────

CRYPTOMINER_PATTERNS = [
    r'coinhive\.min\.js', r'coinhive\.com',
    r'coin-hive\.com', r'authedmine\.com',
    r'crypto-loot\.com', r'cryptoloot\.pro',
    r'webmine\.pro', r'monerominer',
    r'deepminer\.js', r'cloudcoins\.co',
    r'CoinImp\.min\.js', r'coinimp\.com',
    r'jsecoin\.com', r'webminepool\.com',
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random)."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _is_dga_like(hostname: str) -> bool:
    """Heuristic check for DGA-like (randomly generated) domain names."""
    # Strip TLD
    parts = hostname.split('.')
    if len(parts) < 2:
        return False
    main_label = parts[0]

    # DGA indicators: high entropy, mostly consonants, long numeric sequences
    if len(main_label) < 4:
        return False

    entropy = _calculate_entropy(main_label)
    if entropy > 3.5 and len(main_label) >= 10:
        return True

    # High ratio of consonants to vowels
    vowels = set('aeiou')
    consonants = sum(1 for c in main_label.lower() if c.isalpha() and c not in vowels)
    alpha_count = sum(1 for c in main_label if c.isalpha())
    if alpha_count > 0 and consonants / alpha_count > 0.8 and len(main_label) >= 8:
        return True

    # Long numeric sequences
    if re.search(r'\d{5,}', main_label):
        return True

    return False


def _check_suspicious_tld(hostname: str) -> Optional[dict]:
    """Check if the domain uses a suspicious TLD."""
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return {
                'type': 'suspicious_tld',
                'value': tld,
                'severity': 'medium',
                'description': f'Domain uses {tld} — a TLD frequently associated with phishing and abuse',
            }
    return None


def _check_domain_age(recon_data: dict) -> Optional[dict]:
    """Check domain age from WHOIS data — young domains are suspicious."""
    whois_data = recon_data.get('whois', {}) or {}
    creation_date = whois_data.get('creation_date') or whois_data.get('created')

    if not creation_date:
        return None

    try:
        from datetime import datetime, timezone
        if isinstance(creation_date, str):
            # Try common date formats
            for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d', '%d-%b-%Y'):
                try:
                    dt = datetime.strptime(creation_date[:19], fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
        else:
            dt = creation_date

        now = datetime.now(timezone.utc)
        if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        age_days = (now - dt).days

        if age_days < 30:
            return {
                'type': 'young_domain',
                'value': f'{age_days} days old',
                'severity': 'high',
                'description': f'Domain registered only {age_days} days ago — very young domains are frequently used for phishing',
            }
        elif age_days < 180:
            return {
                'type': 'young_domain',
                'value': f'{age_days} days old',
                'severity': 'medium',
                'description': f'Domain is {age_days} days old — relatively new, warrants additional scrutiny',
            }
    except Exception:
        pass

    return None


def _check_phishing_keywords(hostname: str, subdomains: list) -> list:
    """Check for phishing-related keywords in domain and subdomains."""
    indicators = []
    all_names = [hostname] + subdomains

    for name in all_names:
        for kw_pattern in PHISHING_KEYWORDS:
            if re.search(kw_pattern, name, re.I):
                indicators.append({
                    'type': 'phishing_keyword',
                    'value': name,
                    'severity': 'high',
                    'description': f'Domain/subdomain "{name}" contains phishing-associated keyword pattern',
                })
                break  # One match per name is enough

    return indicators


def _check_ip_reputation(recon_data: dict) -> dict:
    """Basic IP reputation check based on known ranges."""
    dns_data = recon_data.get('dns', {}) or {}
    ip_addresses = dns_data.get('ip_addresses', [])

    ip_score = 70  # Default neutral score

    for ip in ip_addresses if isinstance(ip_addresses, list) else []:
        ip_str = ip.get('value', ip) if isinstance(ip, dict) else str(ip)

        for prefix in _SUSPICIOUS_IP_PREFIXES:
            if ip_str.startswith(prefix):
                ip_score = min(ip_score, 30)
                break

        for prefix in _CLOUD_IP_PREFIXES:
            if ip_str.startswith(prefix):
                ip_score = max(ip_score, 60)
                break

    return {'ip_score': ip_score, 'checked_ips': len(ip_addresses) if isinstance(ip_addresses, list) else 0}


def _check_cryptominer(recon_data: dict) -> list:
    """Check for cryptocurrency mining script indicators."""
    indicators = []

    js_data = recon_data.get('js_analysis', {}) or {}
    scripts = js_data.get('findings', js_data.get('scripts', []))

    for script in scripts if isinstance(scripts, list) else []:
        content = script.get('content', script.get('url', '')) if isinstance(script, dict) else str(script)
        for pattern in CRYPTOMINER_PATTERNS:
            if re.search(pattern, content, re.I):
                indicators.append({
                    'type': 'cryptominer',
                    'value': content[:100],
                    'severity': 'critical',
                    'description': 'Cryptocurrency mining script detected — potential malicious injection',
                })
                break

    return indicators


def _check_whois_privacy(recon_data: dict) -> Optional[dict]:
    """Check WHOIS privacy/registrant redaction as an indicator."""
    whois_data = recon_data.get('whois', {}) or {}
    registrant = whois_data.get('registrant', whois_data.get('registrant_name', ''))

    privacy_patterns = re.compile(
        r'privacy|redacted|protected|whoisguard|domains\s*by\s*proxy|'
        r'contact\s*privacy|identity\s*protect|withheld',
        re.I,
    )

    if isinstance(registrant, str) and privacy_patterns.search(registrant):
        return {
            'type': 'whois_privacy',
            'value': 'Registrant information redacted',
            'severity': 'low',
            'description': 'WHOIS registrant data is hidden behind a privacy service — common for both legitimate and malicious domains',
        }

    return None


def _determine_threat_profile(threat_level: str, indicators: list) -> str:
    """Generate an overall threat profile label."""
    if threat_level == 'critical':
        return 'potentially_malicious'
    elif threat_level == 'high':
        return 'suspicious'
    elif threat_level == 'medium':
        return 'elevated_risk'
    else:
        return 'legitimate_business'


def _calculate_threat_level(indicators: list) -> str:
    """Calculate overall threat level from indicators."""
    severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    if not indicators:
        return 'low'

    max_sev = max(severity_scores.get(ind.get('severity', 'low'), 0) for ind in indicators)
    total_weight = sum(severity_scores.get(ind.get('severity', 'low'), 0) for ind in indicators)

    if max_sev >= 4 or total_weight >= 10:
        return 'critical'
    elif max_sev >= 3 or total_weight >= 6:
        return 'high'
    elif max_sev >= 2 or total_weight >= 3:
        return 'medium'
    return 'low'


def _calculate_domain_score(hostname: str, indicators: list) -> int:
    """Score domain reputation 0-100 (higher is better/safer)."""
    score = 80  # Start with a neutral-positive baseline

    severity_penalty = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
    for ind in indicators:
        score -= severity_penalty.get(ind.get('severity', 'low'), 0)

    return max(min(score, 100), 0)


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_threat_intel(target_url: str, recon_data: Optional[dict] = None) -> dict:
    """
    Enrich recon findings with threat intelligence context.

    Args:
        target_url: The target URL being scanned.
        recon_data: Aggregated dict of all prior recon module results.

    Returns:
        Standardised result dict with legacy keys:
        ``threat_level``, ``indicators``, ``reputation``,
        ``abuse_indicators``, ``threat_profile``, ``issues``.
    """
    start = time.time()
    result = create_result('threat_intel', target_url)

    # Legacy keys
    result['threat_level'] = 'low'
    result['indicators'] = []
    result['reputation'] = {'domain_score': 80, 'ip_score': 70}
    result['abuse_indicators'] = []
    result['threat_profile'] = 'legitimate_business'
    result['issues'] = []

    if recon_data is None:
        recon_data = {}

    hostname = extract_hostname(target_url)
    extract_root_domain(hostname) if hostname else ''

    logger.info('Starting threat intelligence enrichment for %s', target_url)

    try:
        # ── Check 1: Domain name entropy / DGA detection ───────────────
        result['stats']['total_checks'] += 1
        try:
            if hostname and _is_dga_like(hostname):
                indicator = {
                    'type': 'dga_domain',
                    'value': hostname,
                    'severity': 'high',
                    'description': f'Domain "{hostname}" has characteristics of algorithmically generated names (DGA)',
                }
                result['indicators'].append(indicator)
                add_finding(result, indicator)
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'DGA check: {exc}')

        # ── Check 2: Suspicious TLD ───────────────────────────────────
        result['stats']['total_checks'] += 1
        try:
            tld_indicator = _check_suspicious_tld(hostname) if hostname else None
            if tld_indicator:
                result['indicators'].append(tld_indicator)
                add_finding(result, tld_indicator)
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'TLD check: {exc}')

        # ── Check 3: Domain age ────────────────────────────────────────
        result['stats']['total_checks'] += 1
        try:
            age_indicator = _check_domain_age(recon_data)
            if age_indicator:
                result['indicators'].append(age_indicator)
                add_finding(result, age_indicator)
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Domain age check: {exc}')

        # ── Check 4: Phishing keywords ─────────────────────────────────
        result['stats']['total_checks'] += 1
        try:
            subs_data = recon_data.get('subdomains', {}) or {}
            sub_list = subs_data.get('subdomains', subs_data.get('findings', []))
            subdomain_names = []
            for s in sub_list if isinstance(sub_list, list) else []:
                name = s.get('subdomain', s.get('name', '')) if isinstance(s, dict) else str(s)
                if name:
                    subdomain_names.append(name)

            phishing_indicators = _check_phishing_keywords(hostname, subdomain_names)
            for ind in phishing_indicators:
                result['indicators'].append(ind)
                result['abuse_indicators'].append(ind)
                add_finding(result, ind)
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Phishing keyword check: {exc}')

        # ── Check 5: IP reputation ─────────────────────────────────────
        result['stats']['total_checks'] += 1
        try:
            ip_rep = _check_ip_reputation(recon_data)
            result['reputation']['ip_score'] = ip_rep['ip_score']

            if ip_rep['ip_score'] < 40:
                indicator = {
                    'type': 'suspicious_ip',
                    'value': f"IP score: {ip_rep['ip_score']}/100",
                    'severity': 'medium',
                    'description': 'One or more resolved IPs fall within ranges known for abuse',
                }
                result['indicators'].append(indicator)
                add_finding(result, indicator)
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'IP reputation check: {exc}')

        # ── Check 6: Cryptominer detection ─────────────────────────────
        result['stats']['total_checks'] += 1
        try:
            miner_indicators = _check_cryptominer(recon_data)
            for ind in miner_indicators:
                result['indicators'].append(ind)
                result['abuse_indicators'].append(ind)
                add_finding(result, ind)
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Cryptominer check: {exc}')

        # ── Check 7: WHOIS privacy ─────────────────────────────────────
        result['stats']['total_checks'] += 1
        try:
            privacy_indicator = _check_whois_privacy(recon_data)
            if privacy_indicator:
                result['indicators'].append(privacy_indicator)
                add_finding(result, privacy_indicator)
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'WHOIS privacy check: {exc}')

        # ── Final: Calculate overall threat level & profile ────────────
        result['threat_level'] = _calculate_threat_level(result['indicators'])
        result['reputation']['domain_score'] = _calculate_domain_score(hostname, result['indicators'])
        result['threat_profile'] = _determine_threat_profile(result['threat_level'], result['indicators'])

        # Populate issues for backward compat
        for ind in result['indicators']:
            sev = ind.get('severity', 'info').upper()
            result['issues'].append(f"{sev}: {ind.get('description', ind.get('type', 'Unknown indicator'))}")

    except Exception as exc:
        msg = f'Threat intelligence enrichment error: {exc}'
        logger.error(msg, exc_info=True)
        result['errors'].append(msg)

    logger.info(
        'Threat intelligence complete for %s — level=%s, %d indicators, profile=%s',
        target_url, result['threat_level'],
        len(result['indicators']), result['threat_profile'],
    )

    return finalize_result(result, start)
