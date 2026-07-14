"""
Advanced WAF Evasion Tester — Wraps the Phase 32 WAF evasion engines
into the BaseTester interface.

Tests a target for WAF presence, then probes whether the WAF can be
bypassed using fingerprint-specific, encoding, fragmentation, and
request-mutation techniques.
"""
import logging

from apps.scanning.engine.testers.base_tester import BaseTester
from apps.scanning.engine.waf_evasion_v2 import (
    AdvancedWAFEvasion,
)

logger = logging.getLogger(__name__)

# ── Probe payloads (benign-looking patterns WAFs typically block) ────────────
_PROBE_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "../../../etc/passwd",
    "${7*7}",
    "{{7*7}}",
]

# ── Severity mapping by bypass category ──────────────────────────────────────
_BYPASS_SEVERITY = {
    'fingerprint_bypass': 'high',
    'encoding_bypass': 'high',
    'fragmentation_bypass': 'high',
    'content_type_bypass': 'medium',
    'hpp_bypass': 'medium',
    'method_override_bypass': 'medium',
}

# ── CWE per category ────────────────────────────────────────────────────────
_BYPASS_CWE = {
    'fingerprint_bypass': 'CWE-693',
    'encoding_bypass': 'CWE-693',
    'fragmentation_bypass': 'CWE-693',
    'content_type_bypass': 'CWE-436',
    'hpp_bypass': 'CWE-235',
    'method_override_bypass': 'CWE-436',
}


class AdvancedWAFEvasionTester(BaseTester):
    """Phase 32 — Advanced WAF Evasion testing."""

    TESTER_NAME = 'Advanced WAF Evasion'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        if not url:
            return vulns

        # Determine WAF products from recon or from probing
        waf_info = self._get_waf_info(recon_data)
        waf_products = waf_info.get('products', [])

        engine = AdvancedWAFEvasion(waf_products=waf_products)

        # 1. Find which probe actually gets blocked
        blocked_payload = self._find_blocked_payload(url)
        if not blocked_payload:
            # Nothing is blocked — no WAF to bypass
            return vulns

        # 2. Fingerprint-specific bypass
        fp_results = self._test_fingerprint_bypass(url, blocked_payload, engine)
        for r in fp_results:
            vulns.append(self._result_to_vuln(r, url))

        if depth == 'shallow':
            return vulns

        # 3. Encoding chain bypass
        enc_results = self._test_encoding_bypass(url, blocked_payload, engine)
        for r in enc_results:
            vulns.append(self._result_to_vuln(r, url))

        # 4. Fragmentation bypass
        frag_results = self._test_fragmentation_bypass(url, blocked_payload, engine)
        for r in frag_results:
            vulns.append(self._result_to_vuln(r, url))

        if depth != 'deep':
            return vulns

        # 5. Request mutation bypass (deep only)
        mut_results = self._test_mutation_bypass(url, blocked_payload, engine)
        for r in mut_results:
            vulns.append(self._result_to_vuln(r, url))

        return vulns

    # ── Probing ──────────────────────────────────────────────────────────

    def _find_blocked_payload(self, url: str) -> str:
        """Send probe payloads and return the first one that gets blocked."""
        for payload in _PROBE_PAYLOADS:
            resp = self._make_request(
                'GET', url, params={'test': payload},
            )
            if not resp:
                continue
            status = getattr(resp, 'status_code', 0)
            if status in (403, 406, 429, 503):
                return payload
        return ''

    # ── Fingerprint bypass ───────────────────────────────────────────────

    def _test_fingerprint_bypass(self, url, blocked_payload, engine):
        results = []
        variants = engine.fingerprint.generate(blocked_payload, max_variants=4)
        for variant in variants:
            resp = self._make_request('GET', url, params={'test': variant})
            if not resp:
                continue
            status = getattr(resp, 'status_code', 0)
            if status not in (403, 406, 429, 503):
                results.append({
                    'category': 'fingerprint_bypass',
                    'detail': 'WAF bypassed with fingerprint-specific encoding',
                    'evidence': f'Variant: {variant[:100]} → HTTP {status}',
                })
                return results
        return results

    # ── Encoding bypass ──────────────────────────────────────────────────

    def _test_encoding_bypass(self, url, blocked_payload, engine):
        results = []
        variants = engine.encoding.generate(blocked_payload, max_variants=6)
        for variant in variants:
            resp = self._make_request('GET', url, params={'test': variant})
            if not resp:
                continue
            status = getattr(resp, 'status_code', 0)
            if status not in (403, 406, 429, 503):
                results.append({
                    'category': 'encoding_bypass',
                    'detail': 'WAF bypassed with encoded payload',
                    'evidence': f'Variant: {variant[:100]} → HTTP {status}',
                })
                return results
        return results

    # ── Fragmentation bypass ─────────────────────────────────────────────

    def _test_fragmentation_bypass(self, url, blocked_payload, engine):
        results = []
        variants = engine.fragmentation.generate(blocked_payload, max_variants=6)
        for variant in variants:
            resp = self._make_request('GET', url, params={'test': variant})
            if not resp:
                continue
            status = getattr(resp, 'status_code', 0)
            if status not in (403, 406, 429, 503):
                results.append({
                    'category': 'fragmentation_bypass',
                    'detail': 'WAF bypassed with fragmented payload',
                    'evidence': f'Variant: {variant[:100]} → HTTP {status}',
                })
                return results
        return results

    # ── Mutation bypass ──────────────────────────────────────────────────

    def _test_mutation_bypass(self, url, blocked_payload, engine):
        results = []

        # Content-Type confusion
        for ct in engine.mutation.content_type_variants():
            resp = self._make_request(
                'POST', url,
                data=blocked_payload,
                headers={'Content-Type': ct},
            )
            if not resp:
                continue
            status = getattr(resp, 'status_code', 0)
            if status not in (403, 406, 429, 503):
                results.append({
                    'category': 'content_type_bypass',
                    'detail': f'WAF bypassed with Content-Type: {ct}',
                    'evidence': f'POST with Content-Type: {ct} → HTTP {status}',
                })
                return results

        # HPP
        for hpp in engine.mutation.hpp_variants('q', blocked_payload):
            resp = self._make_request(
                'GET', url + '?' + hpp,
            )
            if not resp:
                continue
            status = getattr(resp, 'status_code', 0)
            if status not in (403, 406, 429, 503):
                results.append({
                    'category': 'hpp_bypass',
                    'detail': 'WAF bypassed with HTTP Parameter Pollution',
                    'evidence': f'HPP query: {hpp[:80]} → HTTP {status}',
                })
                return results

        # Method override
        for hdr_dict in engine.mutation.method_override_headers('PUT'):
            resp = self._make_request(
                'POST', url,
                params={'test': blocked_payload},
                headers=hdr_dict,
            )
            if not resp:
                continue
            status = getattr(resp, 'status_code', 0)
            if status not in (403, 406, 429, 503):
                results.append({
                    'category': 'method_override_bypass',
                    'detail': 'WAF bypassed with method override header',
                    'evidence': f'Override header: {hdr_dict} → HTTP {status}',
                })
                return results

        return results

    # ── Helpers ──────────────────────────────────────────────────────────

    def _result_to_vuln(self, result: dict, url: str) -> dict:
        cat = result.get('category', 'fingerprint_bypass')
        severity = _BYPASS_SEVERITY.get(cat, 'medium')
        cwe = _BYPASS_CWE.get(cat, 'CWE-693')

        return self._build_vuln(
            name=f'WAF Evasion: {result["detail"]}',
            severity=severity,
            category='waf_evasion',
            description=f'The WAF protecting this endpoint can be bypassed. {result["detail"]}.',
            impact='Attackers can send malicious payloads that evade WAF inspection, '
                   'rendering the WAF protection ineffective.',
            remediation='Review WAF rules and update to handle encoding/fragmentation '
                        'variants. Consider defense-in-depth: WAF + input validation + '
                        'parameterised queries.',
            cwe=cwe,
            cvss=0,
            affected_url=url,
            evidence=result.get('evidence', ''),
        )
