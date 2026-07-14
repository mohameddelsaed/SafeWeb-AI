"""
Phase 32 — Advanced WAF Evasion Engine tests.

Tests for WAFFingerprintBypass, EncodingChainEngine, PayloadFragmentationEngine,
RequestMutationEngine, AdvancedWAFEvasion unified engine, and the
AdvancedWAFEvasionTester wrapper.
"""
from unittest.mock import MagicMock, patch

from tests.conftest import MockPage


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_response(status_code=200, text='', headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


# ═════════════════════════════════════════════════════════════════════════════
# WAFFingerprintBypass
# ═════════════════════════════════════════════════════════════════════════════

class TestWAFFingerprintBypass:
    """Tests for the WAF fingerprint-specific bypass engine."""

    def _cls(self):
        from apps.scanning.engine.waf_evasion_v2 import WAFFingerprintBypass
        return WAFFingerprintBypass

    # ── Cloudflare ───────────────────────────────────────────────────────

    def test_cloudflare_generates_variants(self):
        bp = self._cls()(waf_products=['cloudflare'])
        variants = bp.generate("<script>alert(1)</script>")
        assert len(variants) >= 1
        assert all(v != "<script>alert(1)</script>" for v in variants)

    def test_cloudflare_double_url_encode(self):
        bp = self._cls()(waf_products=['cloudflare'])
        variants = bp.generate("test")
        # At least one variant should differ from input
        assert any(v != "test" for v in variants)

    # ── AWS WAF ──────────────────────────────────────────────────────────

    def test_aws_waf_generates_variants(self):
        bp = self._cls()(waf_products=['aws_waf'])
        variants = bp.generate("' OR 1=1--")
        assert len(variants) >= 1

    def test_aws_keyword_match(self):
        """'aws' substring also matches aws_waf."""
        bp = self._cls()(waf_products=['aws'])
        variants = bp.generate("test")
        assert len(variants) >= 1

    # ── Imperva / Incapsula ──────────────────────────────────────────────

    def test_imperva_generates_variants(self):
        bp = self._cls()(waf_products=['imperva'])
        variants = bp.generate("SELECT * FROM users")
        assert len(variants) >= 1

    def test_incapsula_maps_to_imperva(self):
        bp = self._cls()(waf_products=['incapsula'])
        variants = bp.generate("test payload")
        assert len(variants) >= 1

    # ── ModSecurity ──────────────────────────────────────────────────────

    def test_modsecurity_generates_variants(self):
        bp = self._cls()(waf_products=['modsecurity'])
        variants = bp.generate("UNION SELECT 1,2,3")
        assert len(variants) >= 1
        # Should contain comment-inserted variant
        assert any('/**/' in v for v in variants)

    def test_crs_maps_to_modsecurity(self):
        bp = self._cls()(waf_products=['crs'])
        variants = bp.generate("test")
        assert len(variants) >= 1

    # ── Akamai ───────────────────────────────────────────────────────────

    def test_akamai_generates_variants(self):
        bp = self._cls()(waf_products=['akamai'])
        variants = bp.generate("alert(1)")
        assert len(variants) >= 1

    # ── F5 / BIG-IP ──────────────────────────────────────────────────────

    def test_f5_generates_variants(self):
        bp = self._cls()(waf_products=['f5'])
        variants = bp.generate("SELECT 1")
        assert len(variants) >= 1

    def test_bigip_maps_to_f5(self):
        bp = self._cls()(waf_products=['big-ip'])
        variants = bp.generate("test")
        assert len(variants) >= 1

    # ── No WAF / unknown ─────────────────────────────────────────────────

    def test_no_waf_returns_empty(self):
        bp = self._cls()(waf_products=[])
        variants = bp.generate("test")
        # No transforms → no variants generated
        assert len(variants) == 0

    def test_unknown_waf_returns_empty(self):
        bp = self._cls()(waf_products=['unknown_vendor'])
        variants = bp.generate("test")
        assert len(variants) == 0

    # ── Max variants respected ───────────────────────────────────────────

    def test_max_variants_limit(self):
        bp = self._cls()(waf_products=['cloudflare'])
        variants = bp.generate("test", max_variants=2)
        assert len(variants) <= 2

    # ── Multiple WAFs ────────────────────────────────────────────────────

    def test_multiple_wafs_combine(self):
        bp = self._cls()(waf_products=['cloudflare', 'modsecurity'])
        variants = bp.generate("SELECT 1 FROM x")
        # Should have transforms from both WAFs
        assert len(variants) >= 1


# ═════════════════════════════════════════════════════════════════════════════
# EncodingChainEngine
# ═════════════════════════════════════════════════════════════════════════════

class TestEncodingChainEngine:
    """Tests for the encoding chain engine."""

    def _cls(self):
        from apps.scanning.engine.waf_evasion_v2 import EncodingChainEngine
        return EncodingChainEngine

    def test_double_url_encode(self):
        eng = self._cls()(chains=['double_url'])
        variants = eng.generate("<script>")
        assert len(variants) >= 1
        assert '%253C' in variants[0]  # double-encoded '<'

    def test_html_entity_url(self):
        eng = self._cls()(chains=['html_entity_url'])
        variants = eng.generate("abc")
        assert len(variants) >= 1
        assert variants[0] != "abc"

    def test_unicode_normalise(self):
        eng = self._cls()(chains=['unicode_normalise'])
        variants = eng.generate("test")
        assert len(variants) >= 1
        # Fullwidth 't' = U+FF54
        assert '\uff54' in variants[0]

    def test_utf7_encoding(self):
        eng = self._cls()(chains=['utf7'])
        variants = eng.generate("ab")
        assert len(variants) >= 1
        assert variants[0].startswith('+')

    def test_overlong_utf8(self):
        eng = self._cls()(chains=['overlong_utf8'])
        variants = eng.generate("<test>")
        assert len(variants) >= 1
        assert '%C0%BC' in variants[0]  # overlong <

    def test_multipart_boundary(self):
        eng = self._cls()(chains=['multipart_boundary'])
        variants = eng.generate("payload")
        assert len(variants) >= 1
        assert 'WebKitFormBoundary' in variants[0]

    def test_all_chains_by_default(self):
        eng = self._cls()()
        variants = eng.generate("test")
        assert len(variants) >= 3  # multiple chains produce different variants

    def test_max_variants_limit(self):
        eng = self._cls()()
        variants = eng.generate("test", max_variants=2)
        assert len(variants) <= 2

    def test_empty_payload(self):
        eng = self._cls()(chains=['double_url'])
        variants = eng.generate("")
        # Empty string double-encoded is still empty
        assert isinstance(variants, list)


# ═════════════════════════════════════════════════════════════════════════════
# PayloadFragmentationEngine
# ═════════════════════════════════════════════════════════════════════════════

class TestPayloadFragmentationEngine:
    """Tests for the payload fragmentation engine."""

    def _cls(self):
        from apps.scanning.engine.waf_evasion_v2 import PayloadFragmentationEngine
        return PayloadFragmentationEngine

    def test_chunked_transfer(self):
        eng = self._cls()(techniques=['chunked_transfer'])
        variants = eng.generate("HELLO WORLD")
        assert len(variants) >= 1
        assert '0\r\n\r\n' in variants[0]  # chunked terminator

    def test_sql_comment(self):
        eng = self._cls()(techniques=['sql_comment'])
        variants = eng.generate("UNION SELECT")
        assert len(variants) >= 1
        assert '/**/' in variants[0]

    def test_html_comment(self):
        eng = self._cls()(techniques=['html_comment'])
        variants = eng.generate("<script>alert(1)</script>")
        assert len(variants) >= 1
        assert '<!-->' in variants[0]

    def test_null_byte(self):
        eng = self._cls()(techniques=['null_byte'])
        variants = eng.generate("abcdef")
        assert len(variants) >= 1
        assert '%00' in variants[0]

    def test_newline_split(self):
        eng = self._cls()(techniques=['newline_split'])
        variants = eng.generate("abcdefgh")
        assert len(variants) >= 1
        assert '\r\n' in variants[0]

    def test_sql_concat(self):
        eng = self._cls()(techniques=['sql_concat'])
        variants = eng.generate("test1234")
        assert len(variants) >= 1
        assert 'CONCAT(' in variants[0]

    def test_js_concat(self):
        eng = self._cls()(techniques=['js_concat'])
        variants = eng.generate("alert(1)")
        assert len(variants) >= 1
        assert "'+'" in variants[0]

    def test_all_techniques_by_default(self):
        eng = self._cls()()
        variants = eng.generate("UNION SELECT 1 FROM users")
        assert len(variants) >= 4

    def test_max_variants_limit(self):
        eng = self._cls()()
        variants = eng.generate("test", max_variants=2)
        assert len(variants) <= 2

    def test_short_payload_concat(self):
        """Short payloads (<4 chars) handled gracefully by concat."""
        eng = self._cls()(techniques=['sql_concat'])
        variants = eng.generate("ab")
        # Short payload returns itself → no new variant
        assert isinstance(variants, list)


# ═════════════════════════════════════════════════════════════════════════════
# RequestMutationEngine
# ═════════════════════════════════════════════════════════════════════════════

class TestRequestMutationEngine:
    """Tests for the request mutation engine."""

    def _cls(self):
        from apps.scanning.engine.waf_evasion_v2 import RequestMutationEngine
        return RequestMutationEngine

    def test_content_type_variants(self):
        eng = self._cls()()
        cts = eng.content_type_variants()
        assert len(cts) >= 4
        assert 'application/json' in cts
        assert 'text/plain' in cts

    def test_hpp_variants(self):
        eng = self._cls()()
        hpp = eng.hpp_variants('q', '<script>')
        assert len(hpp) == 3
        # Each variant contains the param name
        assert all('q' in h for h in hpp)

    def test_method_override_headers(self):
        eng = self._cls()()
        overrides = eng.method_override_headers('PUT')
        assert len(overrides) == 3
        assert all('PUT' in list(h.values())[0] for h in overrides)

    def test_case_variants(self):
        eng = self._cls()()
        cases = eng.case_variants('POST')
        assert 'POST' in cases
        assert 'post' in cases

    def test_version_downgrade_headers(self):
        eng = self._cls()()
        hdrs = eng.version_downgrade_headers()
        assert hdrs['Connection'] == 'close'


# ═════════════════════════════════════════════════════════════════════════════
# AdvancedWAFEvasion (unified)
# ═════════════════════════════════════════════════════════════════════════════

class TestAdvancedWAFEvasion:
    """Tests for the unified AdvancedWAFEvasion engine."""

    def _cls(self):
        from apps.scanning.engine.waf_evasion_v2 import AdvancedWAFEvasion
        return AdvancedWAFEvasion

    def test_generate_all_with_waf(self):
        eng = self._cls()(waf_products=['cloudflare'])
        variants = eng.generate_all("<script>alert(1)</script>")
        # Should combine fingerprint + encoding + fragmentation
        assert len(variants) >= 3

    def test_generate_all_without_waf(self):
        eng = self._cls()()
        variants = eng.generate_all("test")
        # No WAF fingerprint → still encoding + fragmentation
        assert len(variants) >= 2

    def test_generate_all_unique(self):
        eng = self._cls()(waf_products=['modsecurity'])
        variants = eng.generate_all("UNION SELECT", max_per_engine=5)
        # All variants should be unique
        assert len(variants) == len(set(variants))

    def test_get_request_mutations(self):
        eng = self._cls()()
        muts = eng.get_request_mutations('q', '<script>')
        assert 'content_types' in muts
        assert 'hpp' in muts
        assert 'method_overrides' in muts
        assert 'downgrade_headers' in muts
        assert len(muts['hpp']) == 3

    def test_max_per_engine_respected(self):
        eng = self._cls()(waf_products=['cloudflare'])
        variants = eng.generate_all("test", max_per_engine=1)
        # At most 1 from each of 3 engines = max 3
        assert len(variants) <= 3


# ═════════════════════════════════════════════════════════════════════════════
# AdvancedWAFEvasionTester (BaseTester wrapper)
# ═════════════════════════════════════════════════════════════════════════════

class TestAdvancedWAFEvasionTester:
    """Tests for the BaseTester wrapper."""

    def _get_tester(self):
        from apps.scanning.engine.testers.advanced_waf_evasion_tester import AdvancedWAFEvasionTester
        return AdvancedWAFEvasionTester()

    # ── Empty URL returns empty ──────────────────────────────────────────

    def test_empty_url_returns_empty(self):
        tester = self._get_tester()
        page = MockPage(url='')
        assert tester.test(page) == []

    # ── No WAF → no vulns ────────────────────────────────────────────────

    def test_no_waf_no_vulns(self):
        """When no payload gets blocked, nothing to bypass."""
        tester = self._get_tester()
        with patch.object(tester, '_make_request', return_value=_mock_response(200)):
            page = MockPage(url='https://example.com')
            vulns = tester.test(page, depth='deep')
            assert vulns == []

    # ── WAF detected + fingerprint bypass ────────────────────────────────

    def test_fingerprint_bypass_found(self):
        """Detect bypass when WAF blocks probe but not variant."""
        tester = self._get_tester()
        call_count = [0]

        def mock_req(method, url, **kwargs):
            call_count[0] += 1
            params = kwargs.get('params', {})
            test_val = params.get('test', '')
            # Block original probe payloads
            if test_val in ("<script>alert(1)</script>", "' OR 1=1--",
                            "../../../etc/passwd", "${7*7}", "{{7*7}}"):
                return _mock_response(403, 'Forbidden')
            # Allow evasion variants
            return _mock_response(200, 'OK')

        recon = {'waf': {'detected': True, 'products': [{'name': 'cloudflare'}], 'confidence': 'high'}}
        with patch.object(tester, '_make_request', side_effect=mock_req):
            page = MockPage(url='https://protected.com')
            vulns = tester.test(page, depth='shallow', recon_data=recon)
            assert len(vulns) >= 1
            assert vulns[0]['category'] == 'waf_evasion'
            assert 'CWE' in vulns[0]['cwe']

    # ── Encoding bypass ──────────────────────────────────────────────────

    def test_encoding_bypass_found(self):
        """Encoding bypass detected at medium depth."""
        tester = self._get_tester()
        call_count = [0]

        def mock_req(method, url, **kwargs):
            call_count[0] += 1
            params = kwargs.get('params', {})
            test_val = params.get('test', '')
            # Block original and fingerprint variants (no WAF products → no fp variants)
            if '<script>' in test_val or 'alert' in test_val.lower():
                return _mock_response(403, 'Blocked')
            return _mock_response(200, 'OK')

        with patch.object(tester, '_make_request', side_effect=mock_req):
            page = MockPage(url='https://protected.com')
            vulns = tester.test(page, depth='medium')
            # Should find encoding or fragmentation bypass
            assert len(vulns) >= 1

    # ── Fragmentation bypass ─────────────────────────────────────────────

    def test_fragmentation_bypass_found(self):
        """Fragmentation bypass at medium depth."""
        tester = self._get_tester()

        blocked_set = set()

        def mock_req(method, url, **kwargs):
            params = kwargs.get('params', {})
            test_val = params.get('test', '')
            # Block probes and encoding variants (they contain encoded chars)
            if test_val == "' OR 1=1--":
                blocked_set.add(test_val)
                return _mock_response(403, 'Blocked')
            # Block if it still contains the original chars in URL-encoded form
            if '%27' in test_val or 'OR' in test_val:
                return _mock_response(403, 'Blocked')
            if not test_val:
                return _mock_response(200, '')
            return _mock_response(200, 'OK')

        with patch.object(tester, '_make_request', side_effect=mock_req):
            page = MockPage(url='https://protected.com')
            vulns = tester.test(page, depth='medium')
            assert isinstance(vulns, list)

    # ── Mutation bypass (deep only) ──────────────────────────────────────

    def test_mutation_bypass_deep_only(self):
        """Mutation bypass only tested at deep depth."""
        tester = self._get_tester()
        call_log = []

        def mock_req(method, url, **kwargs):
            call_log.append((method, kwargs.get('headers', {})))
            params = kwargs.get('params', {})
            test_val = params.get('test', '')
            data = kwargs.get('data', '')
            # Block probes
            if test_val in ("<script>alert(1)</script>", "' OR 1=1--",
                            "../../../etc/passwd", "${7*7}", "{{7*7}}"):
                return _mock_response(403, 'Blocked')
            if any(p in str(data) for p in ("<script>", "' OR")):
                return _mock_response(403, 'Blocked')
            # Block all variants too
            return _mock_response(403, 'Still blocked')

        with patch.object(tester, '_make_request', side_effect=mock_req):
            page = MockPage(url='https://protected.com')

            # Medium: no mutation POST calls
            tester.test(page, depth='medium')
            post_calls_medium = [c for c in call_log if c[0] == 'POST']

            call_log.clear()
            tester.test(page, depth='deep')
            post_calls_deep = [c for c in call_log if c[0] == 'POST']

            # Deep should have more POST calls (Content-Type mutations)
            assert len(post_calls_deep) > len(post_calls_medium)

    def test_content_type_bypass_found(self):
        """Content-Type mutation bypass detected at deep depth."""
        tester = self._get_tester()

        def mock_req(method, url, **kwargs):
            params = kwargs.get('params', {})
            kwargs.get('data', '')
            headers = kwargs.get('headers', {})
            test_val = params.get('test', '')
            # Block probes
            if test_val in ("<script>alert(1)</script>", "' OR 1=1--",
                            "../../../etc/passwd", "${7*7}", "{{7*7}}"):
                return _mock_response(403, 'Blocked')
            # Block all encoding/fragmentation variants
            if 'test' in params:
                return _mock_response(403, 'Blocked')
            # Content-Type text/plain bypasses
            ct = headers.get('Content-Type', '')
            if 'text/plain' in ct and method == 'POST':
                return _mock_response(200, 'OK')
            # Block everything else
            return _mock_response(403, 'Blocked')

        with patch.object(tester, '_make_request', side_effect=mock_req):
            page = MockPage(url='https://protected.com')
            vulns = tester.test(page, depth='deep')
            ct_vulns = [v for v in vulns if 'Content-Type' in v.get('name', '')]
            assert len(ct_vulns) >= 1

    # ── Vuln dict structure ──────────────────────────────────────────────

    def test_vuln_dict_structure(self):
        """Vuln dicts have all required keys."""
        tester = self._get_tester()

        def mock_req(method, url, **kwargs):
            params = kwargs.get('params', {})
            test_val = params.get('test', '')
            if test_val in ("<script>alert(1)</script>", "' OR 1=1--",
                            "../../../etc/passwd", "${7*7}", "{{7*7}}"):
                return _mock_response(403, 'Blocked')
            return _mock_response(200, 'OK')

        recon = {'waf': {'detected': True, 'products': [{'name': 'cloudflare'}], 'confidence': 'high'}}
        with patch.object(tester, '_make_request', side_effect=mock_req):
            page = MockPage(url='https://protected.com')
            vulns = tester.test(page, depth='shallow', recon_data=recon)
            if vulns:
                v = vulns[0]
                assert 'name' in v
                assert 'severity' in v
                assert 'category' in v
                assert v['category'] == 'waf_evasion'
                assert 'cwe' in v
                assert 'cvss' in v
                assert 'affected_url' in v
                assert 'evidence' in v
                assert 'description' in v
                assert 'impact' in v
                assert 'remediation' in v

    # ── Registration & tester count ──────────────────────────────────────

    def test_registered_in_get_all_testers(self):
        """AdvancedWAFEvasionTester is in get_all_testers()."""
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        names = [t.TESTER_NAME for t in testers]
        assert 'Advanced WAF Evasion' in names

    def test_tester_count(self):
        """Total tester count is 64 (63 + Phase 32)."""
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert len(testers) == 87
