"""
Scope Expander — Phase 18 Autonomous Hunting.

Intelligently identifies related domains/assets that may be in scope
for an autonomous scan, based on DNS, WHOIS, ASN, certificates, and
page links. All candidates are presented as RECOMMENDATIONS only —
they are NEVER auto-added to the active scan without explicit consent.
"""
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ScopeExpander:
    """
    Recommend additional domains/assets for scope expansion.

    Rules applied (in order of confidence):
      1. Certificate SAN: domains sharing the same TLS cert SAN → high confidence
      2. DNS CNAME: CNAME targets that are subdomains of seed domain → high confidence
      3. WHOIS: same registrant as seed domain → medium confidence
      4. Links: linked domains that share the company name → medium confidence
      5. ASN: IPs in the same Autonomous System → low confidence (flag only)

    All candidates have confidence 0.0–1.0. NEVER auto-expand; surface only.
    """

    # Confidence thresholds
    HIGH = 0.8
    MEDIUM = 0.55
    LOW = 0.35

    def __init__(self, seed_domain: str, recon_data: dict):
        self.seed_domain = self._extract_domain(seed_domain)
        self.recon_data = recon_data or {}

    # ── Public API ────────────────────────────────

    def get_expansion_candidates(self) -> list[dict]:
        """
        Returns a list of candidate dicts:
          {'domain': str, 'reason': str, 'confidence': float}
        Sorted by descending confidence. Duplicates removed.
        """
        candidates: dict[str, dict] = {}  # domain → best entry

        for method in (
            self._from_cert_san,
            self._from_cname,
            self._from_whois,
            self._from_links,
            self._from_asn,
        ):
            try:
                for item in method():
                    domain = item['domain']
                    if domain == self.seed_domain:
                        continue
                    if domain not in candidates or item['confidence'] > candidates[domain]['confidence']:
                        candidates[domain] = item
            except Exception as exc:
                logger.debug(f'Scope expansion method {method.__name__} failed: {exc}')

        result = sorted(candidates.values(), key=lambda x: -x['confidence'])
        logger.info(f'Scope expansion found {len(result)} candidate(s) for {self.seed_domain}')
        return result

    # ── Discovery methods ─────────────────────────

    def _from_cert_san(self) -> list[dict]:
        """Domains found in TLS certificate SAN entries."""
        candidates = []
        cert_info = self.recon_data.get('ssl_info', {}) or {}
        san_list = cert_info.get('subject_alt_names', [])
        for san in san_list:
            domain = san.lstrip('*.')
            if domain and self._is_related(domain):
                candidates.append({
                    'domain': domain,
                    'reason': f'Found in TLS certificate SAN (seed: {self.seed_domain})',
                    'confidence': self.HIGH,
                })
        return candidates

    def _from_cname(self) -> list[dict]:
        """CNAME targets that are subdomains of the seed domain."""
        candidates = []
        dns_data = self.recon_data.get('dns_records', {}) or {}
        cname_records = dns_data.get('CNAME', [])
        for cname in cname_records:
            domain = cname.rstrip('.')
            if domain.endswith('.' + self.seed_domain) or domain == self.seed_domain:
                candidates.append({
                    'domain': domain,
                    'reason': f'DNS CNAME points to subdomain of {self.seed_domain}',
                    'confidence': self.HIGH,
                })
        return candidates

    def _from_whois(self) -> list[dict]:
        """Domains with the same WHOIS registrant."""
        candidates = []
        whois_data = self.recon_data.get('whois', {}) or {}
        registrant = whois_data.get('registrant_email', '') or whois_data.get('registrant_org', '')
        if not registrant:
            return []

        # Look in discovered subdomains' whois (if enriched)
        for sub_info in self.recon_data.get('subdomain_details', []):
            sub_whois = sub_info.get('whois', {}) or {}
            sub_reg = sub_whois.get('registrant_email', '') or sub_whois.get('registrant_org', '')
            if sub_reg and sub_reg == registrant:
                domain = sub_info.get('domain', '')
                if domain:
                    candidates.append({
                        'domain': domain,
                        'reason': f'Same WHOIS registrant as {self.seed_domain}: {registrant}',
                        'confidence': self.MEDIUM,
                    })
        return candidates

    def _from_links(self) -> list[dict]:
        """Linked domains that appear related based on the seed name."""
        candidates = []
        linked_domains = self.recon_data.get('linked_domains', []) or []
        seed_root = self.seed_domain.split('.')[0]  # e.g. "example" from "example.com"
        for domain in linked_domains:
            if seed_root in domain and domain != self.seed_domain:
                candidates.append({
                    'domain': domain,
                    'reason': f'Linked page references domain sharing root name "{seed_root}"',
                    'confidence': self.MEDIUM,
                })
        return candidates

    def _from_asn(self) -> list[dict]:
        """IPs in the same ASN — flagged at low confidence only."""
        candidates = []
        asn_peers = self.recon_data.get('asn_peers', []) or []
        for peer in asn_peers:
            domain = peer.get('domain', '')
            if domain and domain != self.seed_domain:
                candidates.append({
                    'domain': domain,
                    'reason': f'IP found in same ASN as {self.seed_domain} — verify before including',
                    'confidence': self.LOW,
                })
        return candidates

    # ── Helpers ───────────────────────────────────

    def _is_related(self, domain: str) -> bool:
        """Check if a domain is a subdomain of or equal to the seed domain."""
        return domain == self.seed_domain or domain.endswith('.' + self.seed_domain)

    @staticmethod
    def _extract_domain(url_or_domain: str) -> str:
        """Extract the bare domain from a URL or return as-is."""
        if '://' in url_or_domain:
            return urlparse(url_or_domain).netloc.split(':')[0]
        return url_or_domain.split(':')[0]
