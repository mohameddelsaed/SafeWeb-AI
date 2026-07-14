"""
Scope Analyzer — Intelligent scope management for penetration testing.

Implements Amass-style scope management:
  • Domain/subdomain scope validation
  • CIDR range scope checking
  • Wildcard scope pattern matching (`*.example.com`)
  • Out-of-scope filtering with reason codes
  • Third-party / CDN identification
  • Scope expansion recommendations (related ASN, TLDs, subdomains)
"""
import re
import ipaddress
import logging
import time
from datetime import datetime
from urllib.parse import urlparse
from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# ── Well-known third-party / CDN fingerprints ─────────────────────────────
_THIRD_PARTY_DOMAINS = {
    # CDNs
    'cloudflare.com', 'fastly.net', 'akamaiedge.net', 'akamaitechnologies.com',
    'cdn.cloudflare.net', 'cloudfront.net', 'awsglobalaccelerator.com',
    'elb.amazonaws.com', 'azure.com', 'azureedge.net', 'trafficmanager.net',
    'stackpathdns.com', 'maxcdn.com', 'keycdn.com', 'cdn77.com',
    # SaaS / hosting
    'github.io', 'githubusercontent.com', 'gitlab.io', 'pages.dev',
    'netlify.app', 'vercel.app', 'heroku.com', 'herokuapp.com',
    'fly.dev', 'railway.app', 'render.com',
    # Analytics / tracking
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'facebook.com', 'fbcdn.net', 'twitter.com', 'twimg.com',
    'linkedin.com', 'mixpanel.com', 'segment.io', 'segment.com',
    # Customer support
    'zendesk.com', 'zopim.com', 'intercom.io', 'intercom.com', 'crisp.chat',
    # Payment
    'stripe.com', 'stripecdn.com', 'paypal.com', 'braintreegateway.com',
    # Auth
    'auth0.com', 'okta.com', 'onelogin.com', 'ping.com',
}

# ── Common alternative TLD patterns for scope expansion ─────────────────
_ALT_TLDS = ['.net', '.org', '.io', '.co', '.app', '.dev', '.ai', '.cloud']

# ── Privacy / proxy registrar indicators ─────────────────────────────────
_PRIVACY_REGISTRARS = [
    'domains by proxy', 'whoisguard', 'privacyprotect', 'perfect privacy',
    'contactprivacy', 'registrar privacy corp', 'withheld for privacy',
]


def _extract_domain(url_or_domain: str) -> str:
    """Normalise input — strip scheme/path if a URL is passed."""
    s = url_or_domain.strip().lower()
    if '://' in s:
        parsed = urlparse(s)
        return parsed.netloc.split(':')[0]
    return s.split(':')[0]


def _matches_wildcard(subdomain: str, pattern: str) -> bool:
    """
    Check if *subdomain* matches a wildcard *pattern* (``*.example.com``).
    The ``*`` matches exactly one label level.
    """
    if pattern.startswith('*.'):
        suffix = pattern[2:]  # example.com
        # subdomain must end with .suffix and have exactly one extra label
        if subdomain.endswith('.' + suffix):
            prefix = subdomain[: -(len(suffix) + 1)]  # strip .suffix
            if prefix and '.' not in prefix:
                return True
    return False


def _is_ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if *ip* falls within *cidr*."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(ip)
        return addr in net
    except ValueError:
        return False


def _get_root_domain(fqdn: str) -> str:
    """
    Naive root domain extraction (last two labels).
    e.g. sub.sub2.example.co.uk → example.co.uk  (best-effort).
    """
    parts = fqdn.rstrip('.').split('.')
    # Handle common two-part TLDs
    two_part = {'co.uk', 'com.au', 'co.jp', 'co.nz', 'org.uk', 'net.au',
                'com.br', 'co.in', 'co.za', 'gov.uk', 'ac.uk', 'me.uk'}
    if len(parts) >= 3 and f'{parts[-2]}.{parts[-1]}' in two_part:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:]) if len(parts) >= 2 else fqdn


class ScopeChecker:
    """Stateful scope engine.  Build once, call `check()` many times."""

    def __init__(
        self,
        in_scope_domains: list[str] | None = None,
        in_scope_cidrs: list[str] | None = None,
        out_of_scope_domains: list[str] | None = None,
        out_of_scope_cidrs: list[str] | None = None,
    ):
        self.in_scope_domains = [d.lower().strip() for d in (in_scope_domains or [])]
        self.out_of_scope_domains = [d.lower().strip() for d in (out_of_scope_domains or [])]
        self.in_scope_cidrs = [c.strip() for c in (in_scope_cidrs or [])]
        self.out_of_scope_cidrs = [c.strip() for c in (out_of_scope_cidrs or [])]

    def check(self, target: str) -> dict:
        """
        Check whether *target* (domain, FQDN, or IP) is in scope.

        Returns:
            {
                'in_scope':   bool,
                'reason':     str,   — human-readable explanation
                'is_ip':      bool,
                'third_party': bool,
            }
        """
        target = _extract_domain(target) if '/' in target else target.lower().strip()
        is_ip = False

        # ── IP address handling ───────────────────────────────────────────
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            # Check out-of-scope CIDRs first
            for cidr in self.out_of_scope_cidrs:
                if _is_ip_in_cidr(target, cidr):
                    return {'in_scope': False, 'reason': f'IP in out-of-scope CIDR {cidr}',
                            'is_ip': True, 'third_party': False}
            # Check in-scope CIDRs
            for cidr in self.in_scope_cidrs:
                if _is_ip_in_cidr(target, cidr):
                    return {'in_scope': True, 'reason': f'IP in scope CIDR {cidr}',
                            'is_ip': True, 'third_party': False}
            if self.in_scope_cidrs:
                return {'in_scope': False, 'reason': 'IP not in any in-scope CIDR',
                        'is_ip': True, 'third_party': False}
            return {'in_scope': True, 'reason': 'No IP scope defined; defaulting in-scope',
                    'is_ip': True, 'third_party': False}

        # ── Domain / FQDN handling ────────────────────────────────────────

        # Third-party check
        _get_root_domain(target)
        for tp in _THIRD_PARTY_DOMAINS:
            if target == tp or target.endswith('.' + tp):
                return {'in_scope': False, 'reason': f'Third-party domain: {tp}',
                        'is_ip': False, 'third_party': True}

        # Explicit out-of-scope domains / wildcards
        for oos in self.out_of_scope_domains:
            if oos.startswith('*.'):
                if _matches_wildcard(target, oos) or target == oos[2:]:
                    return {'in_scope': False, 'reason': f'Matches out-of-scope pattern {oos}',
                            'is_ip': False, 'third_party': False}
            elif target == oos or target.endswith('.' + oos):
                return {'in_scope': False, 'reason': f'Explicitly out of scope: {oos}',
                        'is_ip': False, 'third_party': False}

        # Explicit in-scope domains / wildcards
        for isd in self.in_scope_domains:
            if isd.startswith('*.'):
                if _matches_wildcard(target, isd) or target == isd[2:]:
                    return {'in_scope': True, 'reason': f'Matches in-scope wildcard {isd}',
                            'is_ip': False, 'third_party': False}
            elif target == isd or target.endswith('.' + isd):
                return {'in_scope': True, 'reason': f'In-scope domain: {isd}',
                        'is_ip': False, 'third_party': False}

        if self.in_scope_domains:
            return {'in_scope': False, 'reason': 'Domain not in any in-scope entry',
                    'is_ip': False, 'third_party': False}
        return {'in_scope': True, 'reason': 'No domain scope defined; defaulting in-scope',
                'is_ip': False, 'third_party': False}


def run_scope_analysis(
    domain: str,
    depth: str = 'medium',
    in_scope_domains: list[str] | None = None,
    in_scope_cidrs: list[str] | None = None,
    out_of_scope_domains: list[str] | None = None,
    out_of_scope_cidrs: list[str] | None = None,
    candidate_subdomains: list[str] | None = None,
    whois_data: dict | None = None,
) -> dict:
    """
    Analyse and manage scope for a penetration testing engagement.

    Args:
        domain:               Primary target domain.
        depth:                Scan depth.
        in_scope_domains:     Explicitly in-scope domains / wildcards.
        in_scope_cidrs:       Explicitly in-scope CIDR ranges.
        out_of_scope_domains: Explicitly out-of-scope domains.
        out_of_scope_cidrs:   Explicitly out-of-scope CIDRs.
        candidate_subdomains: List of discovered subdomains to validate.
        whois_data:           WHOIS result dict (for registrant-based expansion).

    Returns:
        Standardised result dict with extra keys:

            ``in_scope_list``       : list[str]
            ``out_of_scope_list``   : list[str]
            ``third_party_list``    : list[str]
            ``expansion_candidates``: list[str]
            ``scope_summary``       : dict
    """
    start = time.time()
    result = create_result('scope_analysis', domain)
    result['in_scope_list'] = []
    result['out_of_scope_list'] = []
    result['third_party_list'] = []
    result['expansion_candidates'] = []

    checker = ScopeChecker(
        in_scope_domains=in_scope_domains or [domain, f'*.{domain}'],
        in_scope_cidrs=in_scope_cidrs or [],
        out_of_scope_domains=out_of_scope_domains or [],
        out_of_scope_cidrs=out_of_scope_cidrs or [],
    )

    # ── Validate candidate subdomains ────────────────────────────────────
    candidates = list(candidate_subdomains or [domain])
    result['stats']['total_checks'] = len(candidates)

    for candidate in candidates:
        decision = checker.check(candidate)
        result['stats']['successful_checks'] += 1
        if decision['third_party']:
            result['third_party_list'].append(candidate)
        elif decision['in_scope']:
            result['in_scope_list'].append(candidate)
        else:
            result['out_of_scope_list'].append(candidate)

    # ── Scope expansion recommendations ──────────────────────────────────
    if depth in ('medium', 'deep'):
        expansion = []

        # Suggest common alternative TLDs
        root_no_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
        for alt_tld in _ALT_TLDS:
            candidate = root_no_tld + alt_tld
            if candidate != domain:
                expansion.append(candidate)

        # WHOIS-based expansion: registrant organisation
        if whois_data and depth == 'deep':
            org = whois_data.get('org', '') or whois_data.get('registrant_org', '')
            if org:
                # Clean org name to a slug
                slug = re.sub(r'[^a-z0-9]', '-', org.lower())[:30]
                expansion.append(f'{slug}.com')
                expansion.append(f'{slug}.io')

        result['expansion_candidates'] = expansion

    # ── Summary finding ──────────────────────────────────────────────────
    summary = {
        'in_scope_count': len(result['in_scope_list']),
        'out_of_scope_count': len(result['out_of_scope_list']),
        'third_party_count': len(result['third_party_list']),
        'expansion_count': len(result['expansion_candidates']),
    }
    result['scope_summary'] = summary

    add_finding(result, {
        'type': 'scope_analysis',
        'domain': domain,
        **summary,
        'description': (
            f'Scope analysis complete for {domain}: '
            f'{summary["in_scope_count"]} in-scope, '
            f'{summary["out_of_scope_count"]} out-of-scope, '
            f'{summary["third_party_count"]} third-party, '
            f'{summary["expansion_count"]} expansion candidates.'
        ),
        'severity': 'info',
    })

    # Warn about large third-party exposure
    if result['third_party_list']:
        add_finding(result, {
            'type': 'third_party_assets',
            'count': len(result['third_party_list']),
            'examples': result['third_party_list'][:5],
            'description': (
                f'{len(result["third_party_list"])} third-party domain(s) detected. '
                f'These should be excluded from active testing.'
            ),
            'severity': 'info',
        })

    logger.info(
        'Scope analysis for %s: %d in-scope, %d out-of-scope, %d third-party',
        domain,
        summary['in_scope_count'],
        summary['out_of_scope_count'],
        summary['third_party_count'],
    )

    result['metadata']['completed_at'] = datetime.utcnow().isoformat()
    return finalize_result(result, start)
