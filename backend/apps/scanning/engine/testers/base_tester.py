"""
BaseTester — Abstract base class for all vulnerability testers.

Provides recon-intelligence pipeline: WAF detection, tech stack awareness,
and context-aware payload selection helpers available to all testers.
"""
import hashlib
import logging
import time
import requests
import urllib3

from apps.scanning.engine.scoring import severity_from_cvss, SEVERITY_CVSS_MAP
from apps.scanning.engine.waf_evasion import WAFEvasionEngine

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning once at module level
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BaseTester:
    """Abstract base class that all vulnerability testers inherit from."""

    # Override in subclasses
    TESTER_NAME = 'Base'
    REQUEST_TIMEOUT = 10
    MAX_TESTS_PER_PAGE = 50

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SafeWeb AI Scanner/1.0 (Security Assessment)',
        })
        self.session.verify = False

        # Victim session for cross-account testing (IDOR, access control)
        # Set by orchestrator when dual credentials are available
        self.victim_session: requests.Session | None = None

    @property
    def has_victim_session(self) -> bool:
        """True if a victim session is available for cross-account tests."""
        return self.victim_session is not None

    def _make_victim_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request using the victim session.

        Falls back to self.session if no victim session is configured.
        """
        session = self.victim_session or self.session
        kwargs.setdefault('timeout', self.REQUEST_TIMEOUT)
        kwargs.setdefault('allow_redirects', False)
        try:
            response = session.request(method, url, **kwargs)
            time.sleep(0.3)
            return response
        except requests.exceptions.Timeout:
            logger.debug(f'Victim request timeout: {method} {url}')
            return None
        except Exception as e:
            logger.debug(f'Victim request error: {method} {url}: {e}')
            return None

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        """
        Test a single page for vulnerabilities.
        Returns a list of vulnerability dicts ready for Vulnerability.objects.create().

        Args:
            page: Crawled page object (url, status_code, headers, body, forms).
            depth: Scan depth — 'shallow', 'medium', or 'deep'.
            recon_data: Dict from recon phase containing WAF, tech, DNS, cert data.
        """
        raise NotImplementedError('Subclasses must implement test()')

    # ── Recon Intelligence Helpers ────────────────────────────────────────────

    def _get_waf_info(self, recon_data: dict = None) -> dict:
        """Extract WAF detection info from recon data.

        Returns dict with keys: detected (bool), products (list[str]), confidence (str).
        """
        if not recon_data:
            return {'detected': False, 'products': [], 'confidence': 'none'}
        waf = recon_data.get('waf', {})
        return {
            'detected': waf.get('detected', False),
            'products': [p.get('name', '') for p in waf.get('products', [])],
            'confidence': waf.get('confidence', 'none'),
        }

    def _get_tech_stack(self, recon_data: dict = None) -> list:
        """Extract detected technologies from recon data.

        Returns list of dicts with keys: name, category, version.
        """
        if not recon_data:
            return []
        tech = recon_data.get('technologies', {})
        return tech.get('technologies', [])

    def _should_use_waf_bypass(self, recon_data: dict = None) -> bool:
        """Check if WAF bypass payloads should be used."""
        waf_info = self._get_waf_info(recon_data)
        return waf_info['detected']

    def _has_technology(self, recon_data: dict, tech_name: str) -> bool:
        """Check if a specific technology was detected (case-insensitive)."""
        for tech in self._get_tech_stack(recon_data):
            if tech_name.lower() in tech.get('name', '').lower():
                return True
        return False

    def _get_ai_info(self, recon_data: dict = None) -> dict:
        """Extract AI/LLM endpoint info from recon data."""
        if not recon_data:
            return {'detected': False, 'endpoints': [], 'frameworks': []}
        return recon_data.get('ai', {
            'detected': False, 'endpoints': [], 'frameworks': [],
        })

    def _apply_waf_evasion(self, payloads: list, recon_data: dict = None,
                           max_variants: int = 2) -> list:
        """Apply WAF evasion to payloads when a WAF is detected.

        Returns the original payloads plus evasion variants if a WAF
        was detected in recon. Otherwise returns payloads unchanged.
        """
        if not self._should_use_waf_bypass(recon_data):
            return payloads

        waf_info = self._get_waf_info(recon_data)
        engine = WAFEvasionEngine(waf_products=waf_info['products'])

        evaded = []
        seen = set()
        for payload in payloads:
            if payload not in seen:
                evaded.append(payload)
                seen.add(payload)
            for variant in engine.evade(payload, max_variants=max_variants):
                if variant not in seen:
                    evaded.append(variant)
                    seen.add(variant)
        return evaded

    def _get_evasion_headers(self, recon_data: dict = None) -> dict:
        """Get WAF evasion headers if a WAF is detected."""
        if not self._should_use_waf_bypass(recon_data):
            return {}
        waf_info = self._get_waf_info(recon_data)
        engine = WAFEvasionEngine(waf_products=waf_info['products'])
        return engine.get_evasion_headers()

    def _get_cloud_info(self, recon_data: dict = None) -> dict:
        """Extract cloud provider info from recon data.

        Returns dict with keys: providers (list[dict]), cdn (dict|None),
        takeover_risks (list[dict]).
        """
        if not recon_data:
            return {'providers': [], 'cdn': None, 'takeover_risks': []}
        cloud = recon_data.get('cloud', {})
        return {
            'providers': cloud.get('providers', []),
            'cdn': cloud.get('cdn'),
            'takeover_risks': cloud.get('takeover_risks', []),
        }

    def _get_cors_info(self, recon_data: dict = None) -> dict:
        """Extract CORS configuration info from recon data.

        Returns dict with keys: misconfigured (bool), issues (list).
        """
        if not recon_data:
            return {'misconfigured': False, 'issues': []}
        cors = recon_data.get('cors', {})
        return {
            'misconfigured': bool(cors.get('misconfigurations')),
            'issues': cors.get('misconfigurations', []),
        }

    def _get_cert_info(self, recon_data: dict = None) -> dict:
        """Extract certificate info from recon data.

        Returns dict with keys: valid (bool), days_until_expiry (int|None),
        self_signed (bool).
        """
        if not recon_data:
            return {'valid': False, 'days_until_expiry': None, 'self_signed': False}
        cert = recon_data.get('certificate', {})
        return {
            'valid': cert.get('valid', False),
            'days_until_expiry': cert.get('days_until_expiry'),
            'self_signed': cert.get('self_signed', False),
        }

    @staticmethod
    def _vuln_signature(tester_name: str, vuln_name: str, affected_url: str) -> str:
        """Generate a deduplication hash for a vulnerability finding."""
        raw = f'{tester_name}:{vuln_name}:{affected_url}'
        return hashlib.md5(raw.encode()).hexdigest()

    # ── SecLists Payload Augmentation ────────────────────────────────────────

    def _get_seclists_payloads(self, vuln_type: str, recon_data: dict = None,
                               max_payloads: int = 500) -> list:
        """Return context-aware payloads from SecLists for the given vuln type.

        Returns an empty list if SecLists is not installed, so callers degrade
        gracefully to built-in payloads only.

        Args:
            vuln_type:    SecLists category key (e.g. 'sqli', 'xss', 'lfi').
            recon_data:   Recon context dict — used to extract tech stack / depth.
            max_payloads: Hard cap on returned payloads.
        """
        try:
            from apps.scanning.engine.payloads.seclists_manager import SecListsManager
            mgr = SecListsManager()
            if not mgr.is_installed:
                return []
            tech_parts = [t.get('name', '') for t in self._get_tech_stack(recon_data)]
            tech_str = ' '.join(filter(None, tech_parts))
            depth = (recon_data or {}).get('_scan_depth', 'medium')
            return mgr.get_payloads_for_context(
                vuln_type=vuln_type,
                tech_stack=tech_str,
                depth=depth,
                max_payloads=max_payloads,
            )
        except Exception as exc:
            logger.debug('SecLists payload fetch failed (%s): %s', vuln_type, exc)
            return []

    def _augment_payloads_with_seclists(self, payloads: list, vuln_type: str,
                                         recon_data: dict = None) -> list:
        """Merge built-in payloads with SecLists variants, then apply WAF evasion.

        Order: built-in payloads first (highest confidence), SecLists second.
        Duplicates are removed while preserving order.  WAF evasion variants
        are appended last when a WAF is detected.

        Args:
            payloads:   Base payload list (from internal modules).
            vuln_type:  SecLists category key (e.g. 'sqli', 'xss').
            recon_data: Recon context dict.

        Returns:
            Combined, deduplicated, optionally WAF-evaded payload list.
        """
        seclists = self._get_seclists_payloads(vuln_type, recon_data, max_payloads=300)
        seen: set = set(payloads)
        combined = list(payloads)
        for p in seclists:
            if p not in seen:
                combined.append(p)
                seen.add(p)
        if seclists:
            logger.debug(
                'SecLists augmentation (%s): %d built-in + %d new = %d total payloads',
                vuln_type, len(payloads), len(combined) - len(payloads), len(combined),
            )
        return self._apply_waf_evasion(combined, recon_data)

    # ── Discovered Parameters Helper ─────────────────────────────────────────

    def _get_discovered_params(self, page, recon_data: dict = None) -> list:
        """Return additional parameter names discovered by the recon phase.

        Combines param_discovery wordlist hits with any API parameters found
        for the page URL.  Useful for injection testers that want to probe
        parameters not present in the crawled HTML.

        Args:
            page:       Crawled Page object — used for URL matching.
            recon_data: Recon context dict containing param_discovery results.

        Returns:
            List of parameter name strings (may be empty).
        """
        if not recon_data:
            return []
        discovered: list[str] = []
        # param_discovery: {discovered: [{name, url, category, ...}]}
        param_disc = recon_data.get('param_discovery', {})
        page_url = getattr(page, 'url', '') or ''
        for entry in param_disc.get('discovered', []):
            if isinstance(entry, dict):
                # Include params found on same path / same host
                entry_url = entry.get('url', '')
                if not entry_url or entry_url in page_url or page_url.split('?')[0] in entry_url:
                    name = entry.get('name') or entry.get('param')
                    if name and name not in discovered:
                        discovered.append(name)
            elif isinstance(entry, str) and entry not in discovered:
                discovered.append(entry)
        return discovered

    # ── HTTP Helpers ──────────────────────────────────────────────────────────

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request with timeout and error handling."""
        kwargs.setdefault('timeout', self.REQUEST_TIMEOUT)
        kwargs.setdefault('allow_redirects', False)

        try:
            response = self.session.request(method, url, **kwargs)
            time.sleep(0.3)  # Rate limiting
            return response
        except requests.exceptions.Timeout:
            logger.debug(f'Request timeout: {method} {url}')
            return None
        except Exception as e:
            logger.debug(f'Request error: {method} {url}: {e}')
            return None

    def _build_vuln(self, name, severity, category, description, impact,
                    remediation, cwe, cvss, affected_url, evidence):
        """
        Build a vulnerability dict with automatic CVSS ↔ severity alignment.

        If cvss is provided, severity is validated against the CVSS range.
        If only severity is given (cvss=0), a default CVSS is assigned from SEVERITY_CVSS_MAP.
        """
        # Auto-assign CVSS from severity if not explicitly provided
        if cvss == 0 and severity in SEVERITY_CVSS_MAP:
            cvss = SEVERITY_CVSS_MAP[severity]

        # Auto-derive severity from CVSS if severity seems mismatched
        if cvss > 0 and severity not in ('critical', 'high', 'medium', 'low', 'info'):
            severity = severity_from_cvss(cvss)

        return {
            'name': name,
            'severity': severity,
            'category': category,
            'description': description,
            'impact': impact,
            'remediation': remediation,
            'cwe': cwe,
            'cvss': cvss,
            'affected_url': affected_url,
            'evidence': evidence[:2000],  # Truncate evidence
        }

    # ── OOB (Out-of-Band) Callback Helpers ───────────────────────────────

    def _get_oob_manager(self, recon_data: dict = None):
        """Get the OOB manager from recon_data (if available)."""
        if not recon_data:
            return None
        return recon_data.get('_oob_manager')

    def _get_oob_payloads(self, vuln_type: str, param_name: str,
                          target_url: str, recon_data: dict = None) -> list:
        """Get OOB callback payloads for blind vulnerability testing.

        Args:
            vuln_type: 'sqli', 'ssrf', 'xxe', 'rce'/'cmdi', 'ssti'.
            param_name: Parameter name being tested.
            target_url: Target URL.
            recon_data: Recon data dict (must contain '_oob_manager').

        Returns:
            List of (payload_string, callback_id) tuples, or empty list.
        """
        oob_manager = self._get_oob_manager(recon_data)
        if not oob_manager:
            return []
        return oob_manager.get_oob_payloads(vuln_type, param_name, target_url)
