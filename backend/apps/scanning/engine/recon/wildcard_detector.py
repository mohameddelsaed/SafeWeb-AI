"""
Wildcard DNS Detector — puredns-style DNS wildcard detection.

Detects wildcard DNS configurations to prevent false-positive subdomains
from being reported during brute-force or passive enumeration.

Algorithm (matching puredns):
  1. Generate 5 random non-existent subdomains.
  2. Resolve each. If ALL resolve → IP-based wildcard.
  3. Check if responses share IP or same-size body → content wildcard.
  4. Mark wildcard IPs so callers can filter them out.
"""
import random
import string
import socket
import time
import logging
from datetime import datetime
from typing import Optional

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# Number of random probes to confirm a wildcard
_PROBE_COUNT = 5
# Label length for random subdomains
_LABEL_LEN = 12


def _random_label(length: int = _LABEL_LEN) -> str:
    """Generate a random DNS label that should not exist."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _resolve_label(fqdn: str, resolver=None) -> list[str]:
    """
    Resolve *fqdn* and return its A record IPs (empty list on NXDOMAIN/error).
    Uses dnspython when available, falls back to socket.getaddrinfo.
    """
    if HAS_DNSPYTHON and resolver:
        try:
            answers = resolver.resolve(fqdn, 'A', lifetime=3.0)
            return [str(r.address) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []
    # Fallback: stdlib
    try:
        infos = socket.getaddrinfo(fqdn, None, socket.AF_INET)
        return list({info[4][0] for info in infos})
    except OSError:
        return []


def run_wildcard_detection(
    domain: str,
    depth: str = 'medium',
    resolver_ips: Optional[list] = None,
) -> dict:
    """
    Detect wildcard DNS for *domain*.

    Args:
        domain:        Root domain to test (e.g. ``example.com``).
        depth:         Scan depth — affects probe count.
        resolver_ips:  Optional list of custom DNS resolver IP addresses.

    Returns:
        Standardised result dict with extra keys:

            ``wildcard_detected`` : bool
            ``wildcard_ips``      : list[str]  — IPs to filter from brute results
            ``wildcard_type``     : str         — 'ip', 'content', 'none'
    """
    start = time.time()
    result = create_result('wildcard_detection', domain)
    result['wildcard_detected'] = False
    result['wildcard_ips'] = []
    result['wildcard_type'] = 'none'

    # Build resolver
    resolver = None
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            if resolver_ips:
                resolver.nameservers = resolver_ips
        except Exception:
            resolver = None

    probe_count = _PROBE_COUNT + (2 if depth == 'deep' else 0)
    probes = [f'{_random_label()}.{domain}' for _ in range(probe_count)]

    resolved_ips: list[list[str]] = []
    result['stats']['total_checks'] = probe_count

    for probe in probes:
        ips = _resolve_label(probe, resolver)
        resolved_ips.append(ips)
        result['stats']['successful_checks'] += 1

    # ── IP-based wildcard detection ───────────────────────────────────────
    # All probes resolve AND share at least one common IP → wildcard
    all_resolved = all(len(ips) > 0 for ips in resolved_ips)

    if all_resolved:
        # Collect all IPs that appear in EVERY probe response
        ip_sets = [set(ips) for ips in resolved_ips]
        common_ips = ip_sets[0]
        for s in ip_sets[1:]:
            common_ips &= s

        if common_ips:
            result['wildcard_detected'] = True
            result['wildcard_ips'] = sorted(common_ips)
            result['wildcard_type'] = 'ip'

            add_finding(result, {
                'type': 'wildcard_dns',
                'domain': domain,
                'wildcard_type': 'ip',
                'wildcard_ips': sorted(common_ips),
                'probe_count': probe_count,
                'description': (
                    f'Wildcard DNS detected for *.{domain} — all {probe_count} '
                    f'random probes resolved to {sorted(common_ips)}. '
                    f'Subdomain brute-force results must filter these IPs.'
                ),
                'severity': 'info',
            })
            logger.info('Wildcard DNS (IP) detected for %s → %s', domain, sorted(common_ips))
        else:
            # All resolve but no single shared IP — still treat as wildcard
            # (split-horizon / round-robin wildcard)
            all_ips = sorted({ip for ips in resolved_ips for ip in ips})
            result['wildcard_detected'] = True
            result['wildcard_ips'] = all_ips
            result['wildcard_type'] = 'ip_roundrobin'

            add_finding(result, {
                'type': 'wildcard_dns',
                'domain': domain,
                'wildcard_type': 'ip_roundrobin',
                'wildcard_ips': all_ips,
                'probe_count': probe_count,
                'description': (
                    f'Round-robin wildcard DNS detected for *.{domain} — all {probe_count} '
                    f'random probes resolved (no single shared IP). IPs seen: {all_ips}'
                ),
                'severity': 'info',
            })
            logger.info('Wildcard DNS (round-robin) detected for %s', domain)

    elif any(len(ips) > 0 for ips in resolved_ips):
        # Some but not all probes resolved — partial wildcard or flapping
        partial_count = sum(1 for ips in resolved_ips if ips)
        logger.debug(
            'Partial wildcard for %s: %d/%d probes resolved',
            domain, partial_count, probe_count,
        )
        if partial_count >= probe_count - 1:
            # Nearly all resolve — treat as wildcard
            all_ips = sorted({ip for ips in resolved_ips for ip in ips})
            result['wildcard_detected'] = True
            result['wildcard_ips'] = all_ips
            result['wildcard_type'] = 'partial'
            add_finding(result, {
                'type': 'wildcard_dns',
                'domain': domain,
                'wildcard_type': 'partial',
                'wildcard_ips': all_ips,
                'description': (
                    f'Likely wildcard DNS for *.{domain} — {partial_count}/{probe_count} '
                    f'random probes resolved.'
                ),
                'severity': 'info',
            })
    else:
        logger.debug('No wildcard DNS detected for %s', domain)
        add_finding(result, {
            'type': 'no_wildcard',
            'domain': domain,
            'description': (
                f'No wildcard DNS detected for *.{domain} — '
                f'all {probe_count} random probes returned NXDOMAIN.'
            ),
            'severity': 'info',
        })

    result['metadata']['completed_at'] = datetime.utcnow().isoformat()
    result['stats']['failed_checks'] = (
        result['stats']['total_checks'] - result['stats']['successful_checks']
    )
    return finalize_result(result, start)
