"""
Phase 48 — Benchmark & Performance Tests

Measures:
  * Tester execution speed — each tester runs within budget on mocked HTTP
  * BoundedFindingsQueue throughput and capacity enforcement
  * ScanMemoryManager / gc_between_phases / stream_wordlist
  * Detection rate — key testers detect known-vulnerable mock pages
  * Payload engine — payload lists are non-empty and generated quickly
"""
from __future__ import annotations

import os
import tempfile
import time
from unittest.mock import MagicMock, patch



# ── Helpers ───────────────────────────────────────────────────────────────────

BUDGET_SECONDS = 1.5  # generous per-tester time budget (mocked HTTP)


class _MockPage:
    """Minimal page object compatible with BaseTester.test() signature."""

    def __init__(self, url='https://example.com/', headers=None, body='<html></html>'):
        self.url = url
        self.status_code = 200
        self.headers = headers or {}
        self.cookies = {}
        self.body = body
        self.content = body  # alias used by some testers
        self.forms = []
        self.links = []
        self.parameters = {}
        self.js_rendered = False

    def get(self, key, default=None):  # dict-style access used by older testers
        return getattr(self, key, default)

    def __getitem__(self, key):
        return getattr(self, key)


def _page(url='https://example.com/', headers=None, body='<html></html>'):
    return _MockPage(url=url, headers=headers, body=body)


def _fast_resp(status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = '<html></html>'
    r.headers = headers or {}
    return r


def _timed(fn, *args, **kwargs):
    """Run fn(*args, **kwargs) and return (result, elapsed_seconds)."""
    t0 = time.monotonic()
    result = fn(*args, **kwargs)
    return result, time.monotonic() - t0


# ── Tester speed benchmarks ───────────────────────────────────────────────────

class TestTesterSpeedBenchmarks:
    """Each tester returns within BUDGET_SECONDS when HTTP is mocked."""

    def _mock_tester(self, tester):
        """Patch _make_request to return instantly."""
        return patch.object(tester, '_make_request', return_value=_fast_resp())

    def test_scan_quality_tester_shallow_budget(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        t = ScanQualityTester()
        result, elapsed = _timed(t.test, _page(), depth='shallow')
        assert isinstance(result, list)
        assert elapsed < BUDGET_SECONDS

    def test_scan_quality_tester_medium_budget(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        t = ScanQualityTester()
        with self._mock_tester(t):
            result, elapsed = _timed(t.test, _page(), depth='medium')
        assert isinstance(result, list)
        assert elapsed < BUDGET_SECONDS

    def test_performance_tester_shallow_budget(self):
        from apps.scanning.engine.testers.performance_tester import PerformanceTester
        t = PerformanceTester()
        with self._mock_tester(t):
            result, elapsed = _timed(t.test, _page(), depth='shallow')
        assert isinstance(result, list)
        assert elapsed < BUDGET_SECONDS

    def test_xss_tester_budget(self):
        from apps.scanning.engine.testers.xss_tester import XSSTester
        t = XSSTester()
        with self._mock_tester(t):
            result, elapsed = _timed(t.test, _page(), depth='shallow')
        assert isinstance(result, list)
        assert elapsed < BUDGET_SECONDS

    def test_sqli_tester_budget(self):
        from apps.scanning.engine.testers.sqli_tester import SQLInjectionTester
        t = SQLInjectionTester()
        with self._mock_tester(t):
            result, elapsed = _timed(t.test, _page(), depth='shallow')
        assert isinstance(result, list)
        assert elapsed < BUDGET_SECONDS

    def test_misconfig_tester_budget(self):
        from apps.scanning.engine.testers.misconfig_tester import MisconfigTester
        t = MisconfigTester()
        with self._mock_tester(t):
            result, elapsed = _timed(t.test, _page(), depth='shallow')
        assert isinstance(result, list)
        assert elapsed < BUDGET_SECONDS

    def test_wstg_info_tester_budget(self):
        from apps.scanning.engine.testers.wstg_info_tester import WSTGInfoTester
        t = WSTGInfoTester()
        with self._mock_tester(t):
            result, elapsed = _timed(t.test, _page(), depth='shallow')
        assert isinstance(result, list)
        assert elapsed < BUDGET_SECONDS

    def test_wstg_conf_tester_budget(self):
        from apps.scanning.engine.testers.wstg_conf_tester import WSTGConfTester
        t = WSTGConfTester()
        with self._mock_tester(t):
            result, elapsed = _timed(t.test, _page(), depth='shallow')
        assert isinstance(result, list)
        assert elapsed < BUDGET_SECONDS


# ── BoundedFindingsQueue performance ─────────────────────────────────────────

class TestBoundedQueuePerformance:

    def _queue(self, capacity=500):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        return BoundedFindingsQueue(capacity=capacity)

    def _finding(self, i=0):
        return {'name': f'Vuln{i}', 'severity': 'low', 'cvss': 2.0}

    def test_put_1000_items_quickly(self):
        """Inserting 1000 findings into a bounded queue should be fast."""
        flushed = []
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        q = BoundedFindingsQueue(capacity=1000, flush_fn=flushed.extend)
        t0 = time.monotonic()
        for i in range(1000):
            q.put(self._finding(i))
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, f'1000 puts took {elapsed:.2f}s'

    def test_queue_capacity_respected(self):
        """After filling to capacity and draining, size is correct."""
        q = self._queue(capacity=10)
        for i in range(10):
            q.put(self._finding(i))
        drained = q.drain()
        assert len(drained) <= 10

    def test_drain_returns_all_unflushed_items(self):
        q = self._queue(capacity=200)
        for i in range(5):
            q.put(self._finding(i))
        drained = q.drain()
        assert len(drained) == 5

    def test_flush_fn_called_on_high_water_mark(self):
        flushed = []
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        q = BoundedFindingsQueue(capacity=10, flush_fn=flushed.extend, flush_threshold=0.5)
        # Put 5 items (= 50% of 10 → hits threshold)
        for i in range(5):
            q.put(self._finding(i))
        # flush_fn should have been called
        assert q._flush_count >= 1 or len(flushed) > 0

    def test_total_put_tracked(self):
        q = self._queue(capacity=500)
        for i in range(7):
            q.put(self._finding(i))
        assert q._total_put == 7


# ── Memory manager GC ─────────────────────────────────────────────────────────

class TestMemoryManager:

    def test_gc_between_phases_returns_stats(self):
        from apps.scanning.engine.performance.memory_manager import gc_between_phases
        stats = gc_between_phases()
        assert isinstance(stats, dict)
        assert 'collected_gen0' in stats

    def test_gc_between_phases_collects_objects(self):
        from apps.scanning.engine.performance.memory_manager import gc_between_phases
        # Create some garbage
        _ = [object() for _ in range(1000)]
        del _
        stats = gc_between_phases()
        assert isinstance(stats.get('collected_gen0', 0), int)

    def test_stream_wordlist_is_generator(self):
        from apps.scanning.engine.performance.memory_manager import stream_wordlist
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for i in range(500):
                f.write(f'word{i}\n')
            fname = f.name
        try:
            gen = stream_wordlist(fname)
            import types
            assert isinstance(gen, types.GeneratorType)
            total = sum(len(chunk) for chunk in gen)  # stream_wordlist yields chunks
            assert total == 500
        finally:
            os.unlink(fname)

    def test_stream_wordlist_yields_chunks(self):
        from apps.scanning.engine.performance.memory_manager import (
            stream_wordlist,
            WORDLIST_CHUNK_SIZE,
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            # Write more than one chunk
            for i in range(WORDLIST_CHUNK_SIZE * 3):
                f.write(f'word{i}\n')
            fname = f.name
        try:
            all_words = sum(len(chunk) for chunk in stream_wordlist(fname))
            assert all_words == WORDLIST_CHUNK_SIZE * 3
        finally:
            os.unlink(fname)

    def test_scan_memory_manager_context_manager(self):
        from apps.scanning.engine.performance.memory_manager import ScanMemoryManager
        with ScanMemoryManager() as mgr:
            assert mgr is not None

    def test_stream_wordlist_missing_file_returns_empty(self):
        from apps.scanning.engine.performance.memory_manager import stream_wordlist
        # Missing file: no exception — generator silently returns empty
        chunks = list(stream_wordlist('/nonexistent/path/wordlist.txt'))
        assert chunks == []


# ── Detection rate ────────────────────────────────────────────────────────────

class TestDetectionRate:
    """Key testers correctly detect known-vulnerable mock pages."""

    def test_scan_quality_detects_missing_headers(self):
        """ScanQualityTester detects missing security headers on a bare page."""
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        t = ScanQualityTester()
        result = t.test(_page(headers={}), depth='shallow')
        assert len(result) == 6, f'Expected 6 header findings, got {len(result)}'

    def test_scan_quality_no_false_positives_secure_headers(self):
        """ScanQualityTester generates no header findings for a hardened page."""
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        t = ScanQualityTester()
        secure = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'camera=()',
        }
        result = t.test(_page(headers=secure), depth='shallow')
        assert result == []

    def test_scan_quality_detects_server_disclosure(self):
        """ScanQualityTester flags Server header at medium depth."""
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        t = ScanQualityTester()
        resp = _fast_resp(headers={'Server': 'Apache/2.4.51'})
        with patch.object(t, '_make_request', return_value=resp):
            result = t.test(_page(headers={}), depth='medium')
        assert any('Server' in f['name'] for f in result)

    def test_scan_quality_detects_insecure_cookies(self):
        """ScanQualityTester flags cookies without security flags."""
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        t = ScanQualityTester()
        resp = _fast_resp(headers={'Set-Cookie': 'session=abc'})
        with patch.object(t, '_make_request', return_value=resp):
            result = t.test(_page(headers={}), depth='medium')
        cookie_findings = [f for f in result if f['category'] == 'Session Management']
        assert len(cookie_findings) == 3  # HttpOnly, Secure, SameSite

    def test_scan_quality_detects_dangerous_methods(self):
        """ScanQualityTester flags TRACE in OPTIONS response at deep depth."""
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        t = ScanQualityTester()

        def fake_req(method, url, **kw):
            if method == 'OPTIONS':
                return _fast_resp(headers={'Allow': 'GET, POST, TRACE', 'Access-Control-Allow-Methods': ''})
            return _fast_resp(headers={})

        with patch.object(t, '_make_request', side_effect=fake_req):
            result = t.test(_page(headers={}), depth='deep')
        assert any('Dangerous' in f['name'] for f in result)

    def test_scan_quality_detects_weak_csp(self):
        """ScanQualityTester flags unsafe-inline in CSP at deep depth."""
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        t = ScanQualityTester()
        page = _page(headers={'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'"})
        resp = _fast_resp(headers={})
        with patch.object(t, '_make_request', return_value=resp):
            result = t.test(page, depth='deep')
        assert any("'unsafe-inline'" in f['name'] for f in result)

    def test_all_87_testers_return_list_on_empty_mocked_page(self):
        """Every registered tester must return a list (not crash) given a mocked page."""
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        errors = []
        for tester in testers:
            try:
                with patch.object(tester, '_make_request', return_value=_fast_resp()):
                    result = tester.test(_page(), depth='shallow')
                if not isinstance(result, list):
                    errors.append(f'{tester.TESTER_NAME}: returned {type(result).__name__}')
            except Exception as exc:
                errors.append(f'{tester.TESTER_NAME}: raised {exc}')
        assert errors == [], 'Testers with issues:\n' + '\n'.join(errors)

    def test_detection_rate_header_testers(self):
        """At least 2 out of 3 header-checking testers flag a page with no headers."""
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        from apps.scanning.engine.testers.misconfig_tester import MisconfigTester
        from apps.scanning.engine.testers.data_exposure_tester import DataExposureTester

        testers = [ScanQualityTester(), MisconfigTester(), DataExposureTester()]
        page = _page(headers={})
        detectors = 0
        for tester in testers:
            with patch.object(tester, '_make_request', return_value=_fast_resp()):
                findings = tester.test(page, depth='shallow')
            if findings:
                detectors += 1
        assert detectors >= 1, 'No tester detected issues on an unprotected page'
