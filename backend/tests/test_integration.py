"""
Phase 48 — Integration & Pipeline Tests

End-to-end tests exercising the full scan pipeline:
  * Multi-tester pipeline execution and finding aggregation
  * Error isolation — one tester raises, the pipeline continues
  * Registry smoke test — all 87 testers instantiate cleanly and are well-formed
  * Scoring pipeline — severity_from_cvss + calculate_cvss_base
  * Finding structure validation — _build_vuln output meets schema
  * ScanQualityTester end-to-end scenarios
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch



# ── Helpers ───────────────────────────────────────────────────────────────────

class _MockPage:
    """Minimal page object with attribute access (needed by XSSTester etc.)."""

    def __init__(self, url='https://example.com/', headers=None, body='<html></html>'):
        self.url = url
        self.status_code = 200
        self.headers = headers or {}
        self.cookies = {}
        self.body = body
        self.content = body  # alias used by older testers
        self.forms = []
        self.links = []
        self.parameters = {}
        self.js_rendered = False

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __getitem__(self, key):
        return getattr(self, key)


def _page(url='https://example.com/', headers=None, body='<html></html>'):
    return _MockPage(url=url, headers=headers, body=body)


def _resp(status=200, headers=None, text='OK'):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def _run_pipeline(testers, page, depth='medium', recon_data=None):
    """Simplified scan pipeline — mirrors orchestrator logic."""
    all_findings: list[dict] = []
    for t in testers:
        try:
            result = t.test(page, depth=depth, recon_data=recon_data)
            if isinstance(result, list):
                all_findings.extend(result)
        except Exception:
            pass  # error isolation
    return all_findings


# ── Multi-tester pipeline ─────────────────────────────────────────────────────

class TestMultiTesterPipeline:
    """Integration tests for running multiple testers against the same page."""

    def _make_dummy_tester(self, name, findings=None, raise_exc=None):
        """Create a minimal tester stub."""
        class _DummyTester:
            TESTER_NAME = name

            def test(self_, page, depth='medium', recon_data=None):
                if raise_exc:
                    raise raise_exc
                return list(findings or [])

        return _DummyTester()

    def _finding(self, name='Test Vuln', severity='medium'):
        return {
            'name': name, 'severity': severity, 'category': 'Test',
            'description': 'desc', 'impact': 'impact',
            'remediation': 'fix', 'cwe': 'CWE-1', 'cvss': 5.0,
            'affected_url': 'https://example.com/', 'evidence': 'evidence',
        }

    def test_findings_aggregated_from_all_testers(self):
        t1 = self._make_dummy_tester('T1', [self._finding('V1')])
        t2 = self._make_dummy_tester('T2', [self._finding('V2')])
        result = _run_pipeline([t1, t2], _page())
        names = [f['name'] for f in result]
        assert 'V1' in names
        assert 'V2' in names

    def test_empty_page_no_crash(self):
        t1 = self._make_dummy_tester('T1', [])
        result = _run_pipeline([t1], _page())
        assert result == []

    def test_zero_testers_returns_empty(self):
        assert _run_pipeline([], _page()) == []

    def test_order_preserved(self):
        findings = [self._finding(f'V{i}') for i in range(5)]
        testers = [self._make_dummy_tester(f'T{i}', [findings[i]]) for i in range(5)]
        result = _run_pipeline(testers, _page())
        assert [f['name'] for f in result] == [f'V{i}' for i in range(5)]

    def test_depth_parameter_passed_through(self):
        received = []

        class _CaptureTester:
            TESTER_NAME = 'Capture'

            def test(self_, page, depth='medium', recon_data=None):
                received.append(depth)
                return []

        _run_pipeline([_CaptureTester()], _page(), depth='deep')
        assert received == ['deep']

    def test_recon_data_passed_to_each_tester(self):
        received = []

        class _ReconTester:
            TESTER_NAME = 'Recon'

            def test(self_, page, depth='medium', recon_data=None):
                received.append(recon_data)
                return []

        recon = {'waf': 'cloudflare'}
        _run_pipeline([_ReconTester()], _page(), recon_data=recon)
        assert received[0] is recon


# ── Error isolation ───────────────────────────────────────────────────────────

class TestErrorIsolation:
    """If one tester raises an exception the pipeline must continue."""

    def _finding(self):
        return {
            'name': 'OK Vuln', 'severity': 'low', 'category': 'Test',
            'description': 'd', 'impact': 'i', 'remediation': 'r',
            'cwe': 'CWE-1', 'cvss': 2.0,
            'affected_url': 'https://example.com/', 'evidence': 'e',
        }

    def test_exception_does_not_crash_pipeline(self):
        class _BrokenTester:
            TESTER_NAME = 'Broken'

            def test(self_, page, **kw):
                raise RuntimeError('boom')

        class _GoodTester:
            TESTER_NAME = 'Good'

            def test(self_, page, **kw):
                return [{'name': 'SafeVuln', 'severity': 'low', 'category': 'Test',
                          'description': 'd', 'impact': 'i', 'remediation': 'r',
                          'cwe': 'CWE-1', 'cvss': 2.0,
                          'affected_url': 'https://example.com/', 'evidence': 'e'}]

        result = _run_pipeline([_BrokenTester(), _GoodTester()], _page())
        assert len(result) == 1
        assert result[0]['name'] == 'SafeVuln'

    def test_multiple_testers_fail_still_collects_successes(self):
        class _BrokenTester:
            TESTER_NAME = 'B'

            def test(self_, page, **kw):
                raise ValueError('bad')

        class _GoodTester:
            TESTER_NAME = 'G'

            def test(self_, page, **kw):
                return [self._finding()]

        result = _run_pipeline([_BrokenTester(), _BrokenTester(), _GoodTester()], _page())
        assert len(result) == 1

    def test_none_return_handled_gracefully(self):
        class _NoneTester:
            TESTER_NAME = 'None'

            def test(self_, page, **kw):
                return None   # non-list return

        # Should not raise; isinstance(None, list) is False → skip
        result = _run_pipeline([_NoneTester()], _page())
        assert result == []

    def test_non_list_return_handled_gracefully(self):
        class _BadReturnTester:
            TESTER_NAME = 'BR'

            def test(self_, page, **kw):
                return 42  # non-list return

        result = _run_pipeline([_BadReturnTester()], _page())
        assert result == []


# ── Registry smoke test ───────────────────────────────────────────────────────

class TestRegistrySmoke:
    """All registered testers must be well-formed."""

    def setup_method(self):
        from apps.scanning.engine.testers import get_all_testers
        self.testers = get_all_testers()

    def test_tester_count(self):
        assert len(self.testers) == 87

    def test_all_testers_instantiate(self):
        """get_all_testers() must return instantiated objects (not classes)."""
        for t in self.testers:
            assert not isinstance(t, type), f'{t} is a class, not an instance'

    def test_all_testers_have_tester_name_string(self):
        for t in self.testers:
            assert isinstance(t.TESTER_NAME, str), (
                f'{type(t).__name__} has non-string TESTER_NAME'
            )
            assert t.TESTER_NAME, f'{type(t).__name__} has empty TESTER_NAME'

    def test_all_tester_names_unique(self):
        names = [t.TESTER_NAME for t in self.testers]
        assert len(names) == len(set(names)), 'Duplicate TESTER_NAME values found'

    def test_all_testers_implement_test_method(self):
        for t in self.testers:
            assert callable(getattr(t, 'test', None)), (
                f'{type(t).__name__} does not implement test()'
            )

    def test_all_testers_have_make_request(self):
        for t in self.testers:
            assert callable(getattr(t, '_make_request', None)), (
                f'{type(t).__name__} missing _make_request()'
            )

    def test_all_testers_have_build_vuln(self):
        for t in self.testers:
            assert callable(getattr(t, '_build_vuln', None)), (
                f'{type(t).__name__} missing _build_vuln()'
            )


# ── Scoring pipeline ──────────────────────────────────────────────────────────

class TestScoringPipeline:

    def test_severity_from_cvss_critical(self):
        from apps.scanning.engine.scoring import severity_from_cvss
        assert severity_from_cvss(9.5) == 'critical'

    def test_severity_from_cvss_high(self):
        from apps.scanning.engine.scoring import severity_from_cvss
        assert severity_from_cvss(7.5) == 'high'

    def test_severity_from_cvss_medium(self):
        from apps.scanning.engine.scoring import severity_from_cvss
        assert severity_from_cvss(5.0) == 'medium'

    def test_severity_from_cvss_low(self):
        from apps.scanning.engine.scoring import severity_from_cvss
        assert severity_from_cvss(2.0) == 'low'

    def test_severity_from_cvss_zero(self):
        from apps.scanning.engine.scoring import severity_from_cvss
        assert severity_from_cvss(0.0) == 'info'

    def test_calculate_cvss_base_network_vector(self):
        from apps.scanning.engine.scoring import calculate_cvss_base
        score = calculate_cvss_base(av='N', ac='L', pr='N', ui='N', c='H', i='H', a='H')
        assert score >= 9.0  # typical critical

    def test_calculate_cvss_base_local_vector(self):
        from apps.scanning.engine.scoring import calculate_cvss_base
        score = calculate_cvss_base(av='L', ac='H', pr='H', ui='R', c='L', i='N', a='N')
        assert 0.0 < score < 5.0

    def test_calculate_cvss_base_no_impact_zero(self):
        from apps.scanning.engine.scoring import calculate_cvss_base
        score = calculate_cvss_base(av='N', ac='L', pr='N', ui='N', c='N', i='N', a='N')
        assert score == 0.0


# ── Finding structure ─────────────────────────────────────────────────────────

class TestFindingStructure:
    """_build_vuln output must satisfy the vulnerability schema."""

    REQUIRED_KEYS = {'name', 'severity', 'category', 'description',
                     'impact', 'remediation', 'cwe', 'cvss',
                     'affected_url', 'evidence'}

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()

    def _build(self, **overrides):
        defaults = dict(
            name='Test', severity='medium', category='Test Cat',
            description='desc', impact='impact', remediation='fix',
            cwe='CWE-79', cvss=5.0,
            affected_url='https://example.com/', evidence='evidence',
        )
        defaults.update(overrides)
        return self.tester._build_vuln(**defaults)

    def test_finding_has_all_required_keys(self):
        f = self._build()
        assert self.REQUIRED_KEYS.issubset(set(f.keys()))

    def test_finding_severity_is_valid(self):
        valid = {'critical', 'high', 'medium', 'low', 'info'}
        for sev in valid:
            f = self._build(severity=sev, cvss=0)
            assert f['severity'] in valid

    def test_evidence_truncated_to_2000_chars(self):
        long_evidence = 'A' * 5000
        f = self._build(evidence=long_evidence)
        assert len(f['evidence']) <= 2000

    def test_cwe_preserved(self):
        f = self._build(cwe='CWE-79')
        assert f['cwe'] == 'CWE-79'

    def test_cvss_preserved(self):
        f = self._build(cvss=7.5)
        assert f['cvss'] == 7.5

    def test_name_preserved(self):
        f = self._build(name='XSS Vulnerability')
        assert f['name'] == 'XSS Vulnerability'

    def test_affected_url_preserved(self):
        url = 'https://test.example.com/login'
        f = self._build(affected_url=url)
        assert f['affected_url'] == url

    def test_description_preserved(self):
        f = self._build(description='Detailed vuln description.')
        assert f['description'] == 'Detailed vuln description.'


# ── ScanQualityTester full pipeline ──────────────────────────────────────────

class TestScanQualityIntegration:
    """End-to-end scenarios for ScanQualityTester in the pipeline context."""

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()

    def test_totally_insecure_page_many_findings(self):
        """A page with no security headers + insecure cookie + server disclosure."""
        resp = _resp(headers={
            'Set-Cookie': 'session=abc',        # no flags
            'Server': 'Apache/2.4.41 (Ubuntu)',
        })
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester.test(_page(headers={}), depth='medium')
        # 6 missing headers + 3 cookie flags + 1 server disclosure = 10
        assert len(result) >= 8

    def test_secure_page_minimal_findings(self):
        """A well-configured page should yield few or no findings."""
        secure_headers = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'camera=()',
        }
        resp = _resp(headers={
            'Set-Cookie': 'session=abc; HttpOnly; Secure; SameSite=Strict',
        })
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester.test(_page(headers=secure_headers), depth='medium')
        # No header findings, no cookie findings, no server disclosure
        assert len(result) == 0

    def test_pipeline_with_scan_quality_tester(self):
        """ScanQualityTester integrates cleanly into a multi-tester pipeline."""
        resp = _resp(headers={})
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = _run_pipeline([self.tester], _page(headers={}), depth='medium')
        assert isinstance(result, list)
        assert len(result) > 0
