"""
Scope Resolver — Resolves scope types into lists of scannable domains.

For each scope type:
  - single_domain: Returns [target] — subdomains handled in recon phase
  - wildcard:      CT log search + DNS brute → matching domains → HTTP probe
  - wide_scope:    Reverse WHOIS + ASN enum + CT by org → domain list → HTTP probe
"""
import asyncio
import logging

logger = logging.getLogger(__name__)


class ScopeResolver:
    """Resolve a scope definition into a list of live, scannable domains."""

    async def resolve(self, scope_type: str, target: str,
                      seed_domains: list[str] | None = None) -> list[str]:
        seed_domains = seed_domains or []

        if scope_type == 'single_domain':
            return await self._resolve_single_domain(target)
        elif scope_type == 'wildcard':
            return await self._resolve_wildcard(target, seed_domains)
        elif scope_type == 'wide_scope':
            return await self._resolve_wide_scope(target, seed_domains)
        else:
            logger.warning('Unknown scope_type=%s, treating as single_domain', scope_type)
            return await self._resolve_single_domain(target)

    # ── Single Domain ────────────────────────────────────────────────

    async def _resolve_single_domain(self, target: str) -> list[str]:
        """Single domain — return as-is. Subdomain discovery happens in recon."""
        url = self._normalize_url(target)
        return [url]

    # ── Wildcard Domain ──────────────────────────────────────────────

    async def _resolve_wildcard(self, pattern: str,
                                seed_domains: list[str]) -> list[str]:
        """Resolve *.example.com into all matching domains via CT logs."""
        root_domain = self._extract_root_from_wildcard(pattern)
        if not root_domain:
            logger.error('Invalid wildcard pattern: %s', pattern)
            return []

        logger.info('Resolving wildcard scope: %s (root=%s)', pattern, root_domain)

        domains: set[str] = set()

        # CT log discovery
        ct_domains = await asyncio.to_thread(self._ct_log_search, root_domain)
        domains.update(ct_domains)

        # Add seed domains
        for seed in seed_domains:
            normalized = self._normalize_url(seed)
            if normalized:
                domains.add(normalized)

        # HTTP probe to confirm alive
        live_domains = await asyncio.to_thread(self._http_probe, list(domains))

        logger.info('Wildcard scope resolved: %d live domains from %d candidates',
                     len(live_domains), len(domains))
        return sorted(live_domains)

    # ── Wide Scope (Company) ─────────────────────────────────────────

    async def _resolve_wide_scope(self, company: str,
                                  seed_domains: list[str]) -> list[str]:
        """Resolve company name into all associated domains via OSINT.

        Sources: Reverse WHOIS, ASN enumeration, CT logs by org, seed domains.
        """
        logger.info('Resolving wide scope for company: %s', company)

        domains: set[str] = set()

        # Run OSINT sources concurrently
        reverse_whois_task = asyncio.to_thread(self._reverse_whois, company)
        asn_task = asyncio.to_thread(self._asn_enum, company)
        ct_org_task = asyncio.to_thread(self._ct_org_search, company)

        results = await asyncio.gather(
            reverse_whois_task, asn_task, ct_org_task,
            return_exceptions=True,
        )

        for i, result in enumerate(results):
            source = ['reverse_whois', 'asn_enum', 'ct_org_search'][i]
            if isinstance(result, Exception):
                logger.warning('Wide scope source %s failed: %s', source, result)
            else:
                logger.info('Wide scope source %s found %d domains', source, len(result))
                domains.update(result)

        # Add seed domains
        for seed in seed_domains:
            normalized = self._normalize_url(seed)
            if normalized:
                domains.add(normalized)

        # HTTP probe to confirm alive
        live_domains = await asyncio.to_thread(self._http_probe, list(domains))

        logger.info('Wide scope resolved: %d live domains from %d candidates',
                     len(live_domains), len(domains))
        return sorted(live_domains)

    # ── Internal helpers ─────────────────────────────────────────────

    def _normalize_url(self, target: str) -> str:
        """Ensure target has a scheme and return normalized URL."""
        target = target.strip()
        if not target:
            return ''
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        return target

    def _extract_root_from_wildcard(self, pattern: str) -> str:
        """Extract root domain from wildcard pattern like *.example.com."""
        pattern = pattern.strip()
        if pattern.startswith('*.'):
            return pattern[2:]
        return pattern

    def _ct_log_search(self, root_domain: str) -> list[str]:
        """Search CT logs for subdomains of root_domain."""
        try:
            from ..recon.ct_log_enum import _query_crtsh, _extract_subdomains
            entries = _query_crtsh(root_domain)
            subdomains = _extract_subdomains(entries, root_domain)
            # Convert subdomains to full URLs
            return [f'https://{sub}' for sub in subdomains if sub]
        except Exception as exc:
            logger.warning('CT log search failed for %s: %s', root_domain, exc)
            return []

    def _reverse_whois(self, company: str) -> list[str]:
        """Reverse WHOIS lookup by organization name."""
        try:
            from ..recon.whois_recon import reverse_whois
            domains = reverse_whois(company)
            return [f'https://{d}' for d in domains if d]
        except Exception as exc:
            logger.warning('Reverse WHOIS failed for %s: %s', company, exc)
            return []

    def _asn_enum(self, company: str) -> list[str]:
        """ASN enumeration for company — discover IP ranges + reverse DNS."""
        try:
            from ..recon.asn_enum import run_asn_enum
            result = run_asn_enum(company)
            domains = result.get('domains', [])
            return [f'https://{d}' for d in domains if d]
        except Exception as exc:
            logger.warning('ASN enum failed for %s: %s', company, exc)
            return []

    def _ct_org_search(self, company: str) -> list[str]:
        """Search CT logs by organization name."""
        try:
            from ..recon.ct_log_enum import search_by_org
            domains = search_by_org(company)
            return [f'https://{d}' for d in domains if d]
        except Exception as exc:
            logger.warning('CT org search failed for %s: %s', company, exc)
            return []

    def _http_probe(self, urls: list[str]) -> list[str]:
        """Probe URLs to check which are alive. Returns live URLs."""
        if not urls:
            return []

        try:
            import requests
        except ImportError:
            logger.warning('requests library not available — returning all URLs unprobed')
            return urls

        live = []
        for url in urls[:200]:  # Cap at 200 to avoid excessive probing
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True,
                                     verify=False)
                if resp.status_code < 500:
                    live.append(url)
            except Exception:
                # Try HTTP fallback if HTTPS fails
                if url.startswith('https://'):
                    try:
                        http_url = url.replace('https://', 'http://', 1)
                        resp = requests.head(http_url, timeout=5,
                                             allow_redirects=True)
                        if resp.status_code < 500:
                            live.append(http_url)
                    except Exception:
                        pass
        return live
