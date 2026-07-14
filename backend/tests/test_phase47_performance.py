"""
Phase 47 — Performance & Scale v2

Tests for:
  AsyncScanRunner / TesterResult / PageScanResult  (async_scan_runner.py)
  BoundedFindingsQueue / LazyPayloadLoader         (memory_manager.py)
  ScanMemoryManager / stream_wordlist / gc_between_phases
  DistributedScanLock / WorkerAutoScaler           (scale_controller.py)
  ScalingRecommendation / ScanPartitioner / ScanPartition
  PerformanceTester                                (testers/performance_tester.py)
  Registry (count == 86, position == PerformanceTester)
"""
from __future__ import annotations

import os
import tempfile
import threading
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _page(url='https://example.com/'):
    return {'url': url, 'content': '<html></html>', 'headers': {}, 'status_code': 200}


def _resp(status=200, text='OK'):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


class _MockTester:
    TESTER_NAME = 'MockTester'

    def __init__(self, findings=None, raise_exc=None, sleep_sec=0.0):
        self._findings = findings or []
        self._raise = raise_exc
        self._sleep = sleep_sec

    def test(self, page, depth='medium', recon_data=None):
        if self._sleep:
            import time
            time.sleep(self._sleep)
        if self._raise:
            raise self._raise
        return list(self._findings)


class _MockRedis:
    """Minimal in-memory redis stub for DistributedScanLock tests."""

    def __init__(self):
        self._store: dict = {}
        self._expiries: dict = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self._store:
            return None          # key already exists → NX fails
        self._store[key] = value
        if ex is not None:
            self._expiries[key] = ex
        return True

    def get(self, key):
        return self._store.get(key)

    def delete(self, key):
        self._store.pop(key, None)
        self._expiries.pop(key, None)

    def expire(self, key, seconds):
        if key in self._store:
            self._expiries[key] = seconds
            return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Constants
# ─────────────────────────────────────────────────────────────────────────────

class TestConstants:
    def test_default_concurrency(self):
        from apps.scanning.engine.performance.async_scan_runner import DEFAULT_CONCURRENCY
        assert DEFAULT_CONCURRENCY >= 1

    def test_default_tester_timeout(self):
        from apps.scanning.engine.performance.async_scan_runner import DEFAULT_TESTER_TIMEOUT
        assert DEFAULT_TESTER_TIMEOUT > 0

    def test_default_page_timeout(self):
        from apps.scanning.engine.performance.async_scan_runner import DEFAULT_PAGE_TIMEOUT
        assert DEFAULT_PAGE_TIMEOUT > 0

    def test_default_max_pages_concurrent(self):
        from apps.scanning.engine.performance.async_scan_runner import DEFAULT_MAX_PAGES_CONCURRENT
        assert DEFAULT_MAX_PAGES_CONCURRENT >= 1

    def test_queue_capacity(self):
        from apps.scanning.engine.performance.memory_manager import DEFAULT_QUEUE_CAPACITY
        assert DEFAULT_QUEUE_CAPACITY >= 1

    def test_flush_threshold(self):
        from apps.scanning.engine.performance.memory_manager import DEFAULT_FLUSH_THRESHOLD
        assert 0.0 < DEFAULT_FLUSH_THRESHOLD <= 1.0

    def test_wordlist_chunk_size(self):
        from apps.scanning.engine.performance.memory_manager import WORDLIST_CHUNK_SIZE
        assert WORDLIST_CHUNK_SIZE >= 1

    def test_default_lock_timeout(self):
        from apps.scanning.engine.performance.scale_controller import DEFAULT_LOCK_TIMEOUT
        assert DEFAULT_LOCK_TIMEOUT > 0

    def test_min_max_workers(self):
        from apps.scanning.engine.performance.scale_controller import MIN_WORKERS, MAX_WORKERS
        assert MIN_WORKERS >= 1
        assert MAX_WORKERS > MIN_WORKERS

    def test_scale_thresholds(self):
        from apps.scanning.engine.performance.scale_controller import (
            SCALE_UP_THRESHOLD, SCALE_DOWN_THRESHOLD,
        )
        assert SCALE_UP_THRESHOLD > SCALE_DOWN_THRESHOLD >= 0

    def test_perf_tester_thresholds(self):
        from apps.scanning.engine.testers.performance_tester import (
            SLOW_THRESHOLD_MS, VERY_SLOW_THRESHOLD_MS, TIMING_DIFF_THRESHOLD_MS,
        )
        assert SLOW_THRESHOLD_MS > 0
        assert VERY_SLOW_THRESHOLD_MS > SLOW_THRESHOLD_MS
        assert TIMING_DIFF_THRESHOLD_MS > 0


# ─────────────────────────────────────────────────────────────────────────────
# 2. TesterResult
# ─────────────────────────────────────────────────────────────────────────────

class TestTesterResult:
    def test_basic_creation(self):
        from apps.scanning.engine.performance.async_scan_runner import TesterResult
        tr = TesterResult(tester_name='XSS', findings=[{'x': 1}], duration=0.5)
        assert tr.tester_name == 'XSS'
        assert tr.findings == [{'x': 1}]
        assert tr.duration == pytest.approx(0.5)

    def test_defaults(self):
        from apps.scanning.engine.performance.async_scan_runner import TesterResult
        tr = TesterResult(tester_name='T')
        assert tr.findings == []
        assert tr.error is None
        assert tr.timed_out is False
        assert tr.duration == pytest.approx(0.0)

    def test_succeeded_clean(self):
        from apps.scanning.engine.performance.async_scan_runner import TesterResult
        tr = TesterResult(tester_name='T')
        assert tr.succeeded is True

    def test_succeeded_false_on_error(self):
        from apps.scanning.engine.performance.async_scan_runner import TesterResult
        tr = TesterResult(tester_name='T', error='boom')
        assert tr.succeeded is False

    def test_succeeded_false_on_timeout(self):
        from apps.scanning.engine.performance.async_scan_runner import TesterResult
        tr = TesterResult(tester_name='T', timed_out=True)
        assert tr.succeeded is False


# ─────────────────────────────────────────────────────────────────────────────
# 3. PageScanResult
# ─────────────────────────────────────────────────────────────────────────────

class TestPageScanResult:
    def test_basic_creation(self):
        from apps.scanning.engine.performance.async_scan_runner import PageScanResult
        psr = PageScanResult(url='https://x.com', total_duration=1.2)
        assert psr.url == 'https://x.com'
        assert psr.results == []
        assert psr.findings_count == 0
        assert psr.error_count == 0

    def test_all_findings_flat(self):
        from apps.scanning.engine.performance.async_scan_runner import (
            PageScanResult, TesterResult,
        )
        tr1 = TesterResult(tester_name='A', findings=[{'n': 1}, {'n': 2}])
        tr2 = TesterResult(tester_name='B', findings=[{'n': 3}])
        psr = PageScanResult(url='https://x.com', results=[tr1, tr2], total_duration=0)
        assert psr.all_findings() == [{'n': 1}, {'n': 2}, {'n': 3}]

    def test_all_findings_empty(self):
        from apps.scanning.engine.performance.async_scan_runner import PageScanResult
        psr = PageScanResult(url='https://x.com')
        assert psr.all_findings() == []


# ─────────────────────────────────────────────────────────────────────────────
# 4. AsyncScanRunner
# ─────────────────────────────────────────────────────────────────────────────

class TestAsyncScanRunner:
    def test_init_defaults(self):
        from apps.scanning.engine.performance.async_scan_runner import (
            AsyncScanRunner, DEFAULT_CONCURRENCY, DEFAULT_TESTER_TIMEOUT,
        )
        r = AsyncScanRunner()
        assert r.max_concurrency == DEFAULT_CONCURRENCY
        assert r.tester_timeout == pytest.approx(DEFAULT_TESTER_TIMEOUT)

    def test_init_invalid_concurrency(self):
        from apps.scanning.engine.performance.async_scan_runner import AsyncScanRunner
        with pytest.raises(ValueError):
            AsyncScanRunner(max_concurrency=0)

    def test_init_invalid_timeout(self):
        from apps.scanning.engine.performance.async_scan_runner import AsyncScanRunner
        with pytest.raises(ValueError):
            AsyncScanRunner(tester_timeout=0)

    def test_run_sync_returns_page_scan_result(self):
        from apps.scanning.engine.performance.async_scan_runner import (
            AsyncScanRunner, PageScanResult,
        )
        runner = AsyncScanRunner()
        tester = _MockTester(findings=[{'name': 'XSS'}])
        result = runner.run_sync(_page(), [tester])
        assert isinstance(result, PageScanResult)
        assert result.findings_count == 1

    def test_run_sync_error_isolated(self):
        from apps.scanning.engine.performance.async_scan_runner import AsyncScanRunner
        runner = AsyncScanRunner()
        good = _MockTester(findings=[{'name': 'OK'}])
        bad = _MockTester(raise_exc=RuntimeError('fail'))
        result = runner.run_sync(_page(), [good, bad])
        # Good tester findings still captured; error tester isolated
        assert result.findings_count == 1
        assert result.error_count == 1

    def test_run_sync_progress_callback(self):
        from apps.scanning.engine.performance.async_scan_runner import AsyncScanRunner
        seen = []
        runner = AsyncScanRunner(progress_cb=seen.append)
        runner.run_sync(_page(), [_MockTester()])
        assert len(seen) == 1

    def test_run_sync_multiple_testers(self):
        from apps.scanning.engine.performance.async_scan_runner import AsyncScanRunner
        testers = [_MockTester(findings=[{'n': i}]) for i in range(5)]
        result = AsyncScanRunner().run_sync(_page(), testers)
        assert result.findings_count == 5

    def test_tester_timeout_recorded(self):
        from apps.scanning.engine.performance.async_scan_runner import AsyncScanRunner
        # Very short timeout to force a timeout on the sleeping mock
        runner = AsyncScanRunner(tester_timeout=0.05)
        slow = _MockTester(sleep_sec=0.5)
        result = runner.run_sync(_page(), [slow])
        assert result.timeout_count == 1

    def test_get_configuration_keys(self):
        from apps.scanning.engine.performance.async_scan_runner import AsyncScanRunner
        cfg = AsyncScanRunner().get_configuration()
        for key in ('max_concurrency', 'tester_timeout', 'page_timeout'):
            assert key in cfg


# ─────────────────────────────────────────────────────────────────────────────
# 5. BoundedFindingsQueue
# ─────────────────────────────────────────────────────────────────────────────

class TestBoundedFindingsQueue:
    def test_init_defaults(self):
        from apps.scanning.engine.performance.memory_manager import (
            BoundedFindingsQueue, DEFAULT_QUEUE_CAPACITY,
        )
        bq = BoundedFindingsQueue()
        assert bq.capacity == DEFAULT_QUEUE_CAPACITY
        assert bq.size() == 0

    def test_invalid_capacity(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        with pytest.raises(ValueError):
            BoundedFindingsQueue(capacity=0)

    def test_invalid_flush_threshold(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        with pytest.raises(ValueError):
            BoundedFindingsQueue(flush_threshold=0.0)

    def test_put_increments_size(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        bq = BoundedFindingsQueue(capacity=100)
        bq.put({'n': 1})
        bq.put({'n': 2})
        assert bq.size() == 2

    def test_auto_flush_at_threshold(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        flushed = []
        bq = BoundedFindingsQueue(capacity=10, flush_fn=flushed.extend, flush_threshold=0.5)
        for i in range(5):   # 5 >= 10*0.5 → auto-flush
            bq.put({'n': i})
        assert len(flushed) >= 5
        assert bq.size() == 0

    def test_manual_flush(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        flushed = []
        bq = BoundedFindingsQueue(capacity=100, flush_fn=flushed.extend)
        bq.put({'x': 1})
        count = bq.flush()
        assert count == 1
        assert len(flushed) == 1
        assert bq.size() == 0

    def test_drain_clears_without_flush_fn(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        bq = BoundedFindingsQueue(capacity=100)
        bq.put({'x': 1})
        bq.put({'x': 2})
        items = bq.drain()
        assert len(items) == 2
        assert bq.size() == 0

    def test_is_full(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        bq = BoundedFindingsQueue(capacity=3, flush_threshold=1.0)
        assert bq.is_full() is False
        # Bypass put() to avoid the auto-flush that fires at exactly capacity
        for _ in range(3):
            bq._items.append({'x': 1})
        assert bq.is_full() is True

    def test_stats_keys(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        bq = BoundedFindingsQueue(capacity=50)
        bq.put({'x': 1})
        s = bq.stats()
        for key in ('size', 'capacity', 'flush_count', 'total_put', 'utilization'):
            assert key in s

    def test_flush_fn_error_restores_items(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue

        def bad_flush(items):
            raise OSError('disk full')

        bq = BoundedFindingsQueue(capacity=100, flush_fn=bad_flush)
        bq.put({'x': 1})
        bq.flush()
        # Items must be restored after flush_fn failure
        assert bq.size() == 1

    def test_thread_safety(self):
        from apps.scanning.engine.performance.memory_manager import BoundedFindingsQueue
        bq = BoundedFindingsQueue(capacity=1000)
        errors = []

        def worker():
            try:
                for i in range(100):
                    bq.put({'i': i})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert bq.stats()['total_put'] == 500


# ─────────────────────────────────────────────────────────────────────────────
# 6. LazyPayloadLoader
# ─────────────────────────────────────────────────────────────────────────────

class TestLazyPayloadLoader:
    def test_load_calls_loader_once(self):
        from apps.scanning.engine.performance.memory_manager import LazyPayloadLoader
        ldr = LazyPayloadLoader()
        calls = []

        def loader():
            calls.append(1)
            return ['a', 'b']

        ldr.get('sqli', loader)
        ldr.get('sqli', loader)
        assert len(calls) == 1

    def test_cache_hit_rate(self):
        from apps.scanning.engine.performance.memory_manager import LazyPayloadLoader
        ldr = LazyPayloadLoader()
        ldr.get('xss', lambda: [1, 2, 3])
        ldr.get('xss', lambda: [1, 2, 3])
        s = ldr.stats()
        assert s['hit_rate'] > 0

    def test_evict_removes_key(self):
        from apps.scanning.engine.performance.memory_manager import LazyPayloadLoader
        ldr = LazyPayloadLoader()
        ldr.get('key', lambda: 'data')
        removed = ldr.evict('key')
        assert removed is True
        # After eviction, loader must be called again
        calls = []
        ldr.get('key', lambda: calls.append(1) or 'data')
        assert len(calls) == 1

    def test_evict_nonexistent_returns_false(self):
        from apps.scanning.engine.performance.memory_manager import LazyPayloadLoader
        ldr = LazyPayloadLoader()
        assert ldr.evict('missing') is False

    def test_evict_all_clears_cache(self):
        from apps.scanning.engine.performance.memory_manager import LazyPayloadLoader
        ldr = LazyPayloadLoader()
        for k in ('a', 'b', 'c'):
            ldr.get(k, lambda: k)
        count = ldr.evict_all()
        assert count == 3
        assert ldr.stats()['cached'] == 0

    def test_lru_eviction_at_capacity(self):
        from apps.scanning.engine.performance.memory_manager import LazyPayloadLoader
        ldr = LazyPayloadLoader(max_cached=3)
        for k in ('a', 'b', 'c'):
            ldr.get(k, lambda k=k: k)
        # Access 'a' to make it recently used
        ldr.get('a', lambda: 'a')
        # Add 'd' → LRU ('b') should be evicted
        ldr.get('d', lambda: 'd')
        assert ldr.stats()['cached'] == 3
        assert 'b' not in [ldr._cache.get(x) for x in ('a', 'b', 'c', 'd') if x in ldr._cache]

    def test_stats_keys(self):
        from apps.scanning.engine.performance.memory_manager import LazyPayloadLoader
        s = LazyPayloadLoader().stats()
        for key in ('cached', 'max_cached', 'load_count', 'cache_hits', 'hit_rate'):
            assert key in s


# ─────────────────────────────────────────────────────────────────────────────
# 7. stream_wordlist
# ─────────────────────────────────────────────────────────────────────────────

class TestStreamWordlist:
    def _make_file(self, lines: list[str]) -> str:
        fd, path = tempfile.mkstemp(suffix='.txt', text=True)
        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(lines))
        return path

    def test_basic_stream(self):
        from apps.scanning.engine.performance.memory_manager import stream_wordlist
        path = self._make_file(['admin', 'login', 'dashboard'])
        words = [w for chunk in stream_wordlist(path, chunk_size=10) for w in chunk]
        assert words == ['admin', 'login', 'dashboard']

    def test_comments_filtered(self):
        from apps.scanning.engine.performance.memory_manager import stream_wordlist
        path = self._make_file(['# comment', 'admin', '# another', 'login'])
        words = [w for chunk in stream_wordlist(path, chunk_size=10) for w in chunk]
        assert words == ['admin', 'login']

    def test_blank_lines_filtered(self):
        from apps.scanning.engine.performance.memory_manager import stream_wordlist
        path = self._make_file(['admin', '', '   ', 'login'])
        words = [w for chunk in stream_wordlist(path, chunk_size=10) for w in chunk]
        assert words == ['admin', 'login']

    def test_chunk_size_respected(self):
        from apps.scanning.engine.performance.memory_manager import stream_wordlist
        path = self._make_file([str(i) for i in range(10)])
        chunks = list(stream_wordlist(path, chunk_size=3))
        assert all(len(c) <= 3 for c in chunks)
        all_words = [w for c in chunks for w in c]
        assert len(all_words) == 10

    def test_missing_file_no_exception(self):
        from apps.scanning.engine.performance.memory_manager import stream_wordlist
        chunks = list(stream_wordlist('/no/such/file.txt'))
        assert chunks == []


# ─────────────────────────────────────────────────────────────────────────────
# 8. gc_between_phases
# ─────────────────────────────────────────────────────────────────────────────

class TestGcBetweenPhases:
    def test_returns_dict(self):
        from apps.scanning.engine.performance.memory_manager import gc_between_phases
        result = gc_between_phases(log=False)
        assert isinstance(result, dict)

    def test_expected_keys(self):
        from apps.scanning.engine.performance.memory_manager import gc_between_phases
        result = gc_between_phases(log=False)
        for key in ('collected_gen0', 'collected_gen1', 'collected_gen2',
                    'total_collected', 'count_before', 'count_after'):
            assert key in result, f'Missing key: {key}'

    def test_total_is_sum(self):
        from apps.scanning.engine.performance.memory_manager import gc_between_phases
        r = gc_between_phases(log=False)
        assert r['total_collected'] == r['collected_gen0'] + r['collected_gen1'] + r['collected_gen2']

    def test_nonnegative_values(self):
        from apps.scanning.engine.performance.memory_manager import gc_between_phases
        r = gc_between_phases(log=False)
        for val in r.values():
            assert val >= 0


# ─────────────────────────────────────────────────────────────────────────────
# 9. ScanMemoryManager
# ─────────────────────────────────────────────────────────────────────────────

class TestScanMemoryManager:
    def test_context_manager(self):
        from apps.scanning.engine.performance.memory_manager import ScanMemoryManager
        flushed = []
        with ScanMemoryManager(flush_fn=flushed.extend) as mem:
            mem.findings.put({'x': 1})
        # Context exit must flush
        assert len(flushed) == 1

    def test_gc_phase_returns_dict(self):
        from apps.scanning.engine.performance.memory_manager import ScanMemoryManager
        mem = ScanMemoryManager()
        result = mem.gc_phase()
        assert isinstance(result, dict)
        assert 'total_collected' in result

    def test_summary_keys(self):
        from apps.scanning.engine.performance.memory_manager import ScanMemoryManager
        mem = ScanMemoryManager()
        mem.gc_phase()
        s = mem.summary()
        for key in ('findings_stats', 'payload_stats', 'phases_gc', 'total_gc_collected'):
            assert key in s

    def test_payload_loader_accessible(self):
        from apps.scanning.engine.performance.memory_manager import ScanMemoryManager
        mem = ScanMemoryManager()
        data = mem.payloads.get('test', lambda: [1, 2, 3])
        assert data == [1, 2, 3]

    def test_context_clears_payloads(self):
        from apps.scanning.engine.performance.memory_manager import ScanMemoryManager
        with ScanMemoryManager() as mem:
            mem.payloads.get('k', lambda: 'v')
            assert mem.payloads.stats()['cached'] == 1
        assert mem.payloads.stats()['cached'] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 10. DistributedScanLock
# ─────────────────────────────────────────────────────────────────────────────

class TestDistributedScanLock:
    def _lock(self, redis=None, scan_id=1):
        from apps.scanning.engine.performance.scale_controller import DistributedScanLock
        return DistributedScanLock(
            redis or _MockRedis(),
            scan_id=scan_id,
            lock_timeout=60,
            acquire_timeout=0.1,
            poll_interval=0.05,
        )

    def test_acquire_succeeds(self):
        lock = self._lock()
        assert lock.acquire() is True
        assert lock.acquired is True

    def test_release_owned_lock(self):
        lock = self._lock()
        lock.acquire()
        assert lock.release() is True
        assert lock.acquired is False

    def test_second_acquire_fails(self):
        redis = _MockRedis()
        lock1 = self._lock(redis, scan_id=7)
        lock2 = self._lock(redis, scan_id=7)
        lock1.acquire()
        # Non-blocking so we don't wait
        assert lock2.acquire(blocking=False) is False

    def test_is_locked(self):
        redis = _MockRedis()
        lock = self._lock(redis)
        assert lock.is_locked() is False
        lock.acquire()
        assert lock.is_locked() is True

    def test_extend_owned_lock(self):
        redis = _MockRedis()
        lock = self._lock(redis)
        lock.acquire()
        result = lock.extend(30)
        assert result is True

    def test_release_unowned_returns_false(self):
        redis = _MockRedis()
        lock1 = self._lock(redis, scan_id=9)
        lock2 = self._lock(redis, scan_id=9)
        # lock2 acquires — lock1 never acquired
        lock2.acquire()
        assert lock1.release() is False

    def test_context_manager_acquires_and_releases(self):
        redis = _MockRedis()
        lock = self._lock(redis)
        with lock as acquired:
            assert acquired is True
            assert lock.is_locked() is True
        assert lock.is_locked() is False

    def test_lock_key_prefix(self):
        from apps.scanning.engine.performance.scale_controller import DistributedScanLock
        lock = DistributedScanLock(_MockRedis(), scan_id=42)
        assert lock._lock_key.startswith(DistributedScanLock.LOCK_PREFIX)
        assert '42' in lock._lock_key


# ─────────────────────────────────────────────────────────────────────────────
# 11. ScalingRecommendation
# ─────────────────────────────────────────────────────────────────────────────

class TestScalingRecommendation:
    def test_creation(self):
        from apps.scanning.engine.performance.scale_controller import ScalingRecommendation
        rec = ScalingRecommendation(
            queue_depth=100,
            current_workers=2,
            recommended_workers=5,
            action='scale_up',
            reason='High load',
            urgency='high',
        )
        assert rec.action == 'scale_up'
        assert rec.recommended_workers == 5

    def test_default_urgency(self):
        from apps.scanning.engine.performance.scale_controller import ScalingRecommendation
        rec = ScalingRecommendation(
            queue_depth=0, current_workers=1,
            recommended_workers=1, action='maintain', reason='ok',
        )
        assert rec.urgency == 'low'


# ─────────────────────────────────────────────────────────────────────────────
# 12. WorkerAutoScaler
# ─────────────────────────────────────────────────────────────────────────────

class TestWorkerAutoScaler:
    def _scaler(self):
        from apps.scanning.engine.performance.scale_controller import WorkerAutoScaler
        return WorkerAutoScaler(
            min_workers=1, max_workers=10,
            scale_up_threshold=20, scale_down_threshold=2,
            worker_queue_ratio=5,
        )

    def test_scale_up_action(self):
        scaler = self._scaler()
        rec = scaler.assess(queue_depth=25, current_workers=2)
        assert rec.action == 'scale_up'
        assert rec.recommended_workers > 2

    def test_scale_up_high_urgency(self):
        scaler = self._scaler()
        rec = scaler.assess(queue_depth=50, current_workers=2)   # > 20*2
        assert rec.urgency == 'high'

    def test_scale_down_action(self):
        scaler = self._scaler()
        rec = scaler.assess(queue_depth=1, current_workers=5)
        assert rec.action == 'scale_down'
        assert rec.recommended_workers == 1

    def test_maintain_action(self):
        scaler = self._scaler()
        rec = scaler.assess(queue_depth=10, current_workers=3)
        assert rec.action == 'maintain'

    def test_invalid_queue_depth(self):
        from apps.scanning.engine.performance.scale_controller import WorkerAutoScaler
        with pytest.raises(ValueError):
            WorkerAutoScaler().assess(queue_depth=-1, current_workers=2)

    def test_recommended_bounded_by_max(self):
        scaler = self._scaler()
        rec = scaler.assess(queue_depth=1000, current_workers=1)
        assert rec.recommended_workers <= 10

    def test_get_configuration_keys(self):
        cfg = self._scaler().get_configuration()
        for key in ('min_workers', 'max_workers', 'scale_up_threshold',
                    'scale_down_threshold', 'worker_queue_ratio'):
            assert key in cfg


# ─────────────────────────────────────────────────────────────────────────────
# 13. ScanPartition & ScanPartitioner
# ─────────────────────────────────────────────────────────────────────────────

class TestScanPartition:
    def test_creation(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartition
        p = ScanPartition(partition_id=0, worker_index=0, total_workers=4,
                          urls=['a', 'b', 'c'])
        assert p.size == 3

    def test_default_scan_id(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartition
        p = ScanPartition(partition_id=0, worker_index=0, total_workers=1, urls=[])
        assert p.scan_id == 0


class TestScanPartitioner:
    def test_round_robin_returns_n_partitions(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        p = ScanPartitioner(num_workers=4)
        parts = p.partition(['u1', 'u2', 'u3', 'u4', 'u5', 'u6'])
        assert len(parts) == 4

    def test_round_robin_all_urls_covered(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        urls = [f'http://x.com/p{i}' for i in range(20)]
        parts = ScanPartitioner(num_workers=4).partition(urls)
        all_urls = [u for p in parts for u in p.urls]
        assert sorted(all_urls) == sorted(urls)

    def test_hash_bucket_all_urls_covered(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        urls = [f'http://x.com/p{i}' for i in range(20)]
        parts = ScanPartitioner(num_workers=4, strategy='hash_bucket').partition(urls)
        all_urls = [u for p in parts for u in p.urls]
        assert sorted(all_urls) == sorted(urls)

    def test_single_worker(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        urls = ['a', 'b', 'c']
        parts = ScanPartitioner(num_workers=1).partition(urls)
        assert len(parts) == 1
        assert parts[0].size == 3

    def test_invalid_num_workers(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        with pytest.raises(ValueError):
            ScanPartitioner(num_workers=0)

    def test_invalid_strategy(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        with pytest.raises(ValueError):
            ScanPartitioner(num_workers=2, strategy='invalid')

    def test_rebalance(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        urls = [f'http://example.com/{i}' for i in range(12)]
        partitioner = ScanPartitioner(num_workers=3)
        parts = partitioner.partition(urls)
        rebalanced = partitioner.rebalance(parts)
        assert len(rebalanced) == 3
        total = sum(p.size for p in rebalanced)
        assert total == 12

    def test_stats(self):
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        urls = list(range(10))
        parts = ScanPartitioner(num_workers=2).partition(urls)
        s = ScanPartitioner(num_workers=2).stats(parts)
        for key in ('total_urls', 'num_partitions', 'min_size', 'max_size', 'avg_size', 'balance_ratio'):
            assert key in s
        assert s['total_urls'] == 10

    def test_hash_bucket_stable(self):
        """Same URL always maps to same bucket across calls."""
        from apps.scanning.engine.performance.scale_controller import ScanPartitioner
        urls = ['https://a.com', 'https://b.com', 'https://c.com']
        p = ScanPartitioner(num_workers=3, strategy='hash_bucket')
        parts1 = p.partition(urls)
        parts2 = p.partition(urls)
        for p1, p2 in zip(parts1, parts2):
            assert sorted(p1.urls) == sorted(p2.urls)


# ─────────────────────────────────────────────────────────────────────────────
# 14. PerformanceTester
# ─────────────────────────────────────────────────────────────────────────────

class TestPerformanceTester:
    def setup_method(self):
        from apps.scanning.engine.testers.performance_tester import PerformanceTester
        self.tester = PerformanceTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Performance & Scale Engine'

    def test_returns_list(self):
        page = _page()
        with patch.object(self.tester, '_make_request', return_value=_resp(200)):
            result = self.tester.test(page)
        assert isinstance(result, list)

    def test_no_url_returns_empty(self):
        result = self.tester.test({'url': '', 'content': ''})
        assert result == []

    def test_slow_response_finding(self):
        from apps.scanning.engine.testers.performance_tester import (
            PerformanceTester, SLOW_THRESHOLD_MS,
        )
        # Patch time.monotonic so that measured elapsed exceeds SLOW_THRESHOLD_MS
        tester = PerformanceTester()
        half_s = (SLOW_THRESHOLD_MS + 500) / 1000.0  # seconds

        times = [0.0, half_s, half_s, half_s * 2, half_s * 2, half_s * 3]
        idx = [0]

        def fake_time():
            v = times[min(idx[0], len(times) - 1)]
            idx[0] += 1
            return v

        with patch.object(tester, '_make_request', return_value=_resp(200)), \
             patch('apps.scanning.engine.testers.performance_tester.time') as mock_time:
            mock_time.monotonic.side_effect = fake_time
            vulns = tester._test_response_time_baseline('https://example.com/')

        assert len(vulns) >= 1
        assert 'CWE-400' in vulns[0]['cwe']

    def test_very_slow_response_medium_severity(self):
        from apps.scanning.engine.testers.performance_tester import (
            PerformanceTester, VERY_SLOW_THRESHOLD_MS,
        )
        tester = PerformanceTester()
        half_s = (VERY_SLOW_THRESHOLD_MS + 500) / 1000.0

        times = [0.0, half_s, half_s, half_s * 2, half_s * 2, half_s * 3]
        idx = [0]

        def fake_time():
            v = times[min(idx[0], len(times) - 1)]
            idx[0] += 1
            return v

        with patch.object(tester, '_make_request', return_value=_resp(200)), \
             patch('apps.scanning.engine.testers.performance_tester.time') as mock_time:
            mock_time.monotonic.side_effect = fake_time
            vulns = tester._test_response_time_baseline('https://example.com/')

        assert any(v.get('severity') == 'medium' for v in vulns)

    def test_rate_limit_present_no_finding(self):
        # 429 returned → no finding
        with patch.object(self.tester, '_make_request', return_value=_resp(429)):
            vulns = self.tester._test_rate_limit_presence('https://example.com/')
        assert vulns == []

    def test_no_rate_limit_finding(self):
        with patch.object(self.tester, '_make_request', return_value=_resp(200)):
            vulns = self.tester._test_rate_limit_presence('https://example.com/')
        assert len(vulns) == 1
        assert 'CWE-770' in vulns[0]['cwe']
        assert vulns[0]['severity'] == 'medium'

    def test_timing_leak_finding(self):
        from apps.scanning.engine.testers.performance_tester import (
            PerformanceTester, TIMING_DIFF_THRESHOLD_MS,
        )
        tester = PerformanceTester()
        slow_s = (TIMING_DIFF_THRESHOLD_MS + 200) / 1000.0

        # Calls: t0_start, t0_end (valid), t1_start, t1_end (404)
        # valid elapsed = slow_s - 0 = slow_s → slow_s * 1000 ms
        # 404 elapsed = slow_s - slow_s = 0 ms
        # diff = slow_s * 1000 >= TIMING_DIFF_THRESHOLD_MS  ✓
        times = [0.0, slow_s, slow_s, slow_s]
        idx = [0]

        def fake_time():
            v = times[min(idx[0], len(times) - 1)]
            idx[0] += 1
            return v

        with patch.object(tester, '_make_request', return_value=_resp(200)), \
             patch('apps.scanning.engine.testers.performance_tester.time') as mt:
            mt.monotonic.side_effect = fake_time
            vulns = tester._test_timing_leak('https://example.com/')

        assert len(vulns) >= 1
        assert 'CWE-208' in vulns[0]['cwe']

    def test_resource_exhaustion_finding(self):
        with patch.object(self.tester, '_make_request',
                          return_value=_resp(500, 'Internal Server Error')):
            # Need slow response too: patch time to return > SLOW_THRESHOLD
            from apps.scanning.engine.testers.performance_tester import SLOW_THRESHOLD_MS
            slow_s = (SLOW_THRESHOLD_MS + 500) / 1000.0
            times = [0.0, slow_s]
            idx = [0]

            def fake_time():
                v = times[min(idx[0], len(times) - 1)]
                idx[0] += 1
                return v

            with patch('apps.scanning.engine.testers.performance_tester.time') as mt:
                mt.monotonic.side_effect = fake_time
                vulns = self.tester._test_resource_exhaustion('https://example.com/')

        assert len(vulns) >= 1
        assert 'CWE-400' in vulns[0]['cwe']

    def test_depth_shallow_skips_rate_limit(self):
        """shallow depth should not call _test_rate_limit_presence."""
        with patch.object(self.tester, '_make_request', return_value=_resp(200)), \
             patch.object(self.tester, '_test_rate_limit_presence',
                          return_value=[]) as mock_rl:
            self.tester.test(_page(), depth='shallow')
        mock_rl.assert_not_called()

    def test_depth_deep_calls_all_subtests(self):
        """deep depth should call all four sub-tests."""
        with patch.object(self.tester, '_make_request', return_value=_resp(200)), \
             patch.object(self.tester, '_test_response_time_baseline', return_value=[]) as m1, \
             patch.object(self.tester, '_test_rate_limit_presence', return_value=[]) as m2, \
             patch.object(self.tester, '_test_timing_leak', return_value=[]) as m3, \
             patch.object(self.tester, '_test_resource_exhaustion', return_value=[]) as m4:
            self.tester.test(_page(), depth='deep')
        m1.assert_called_once()
        m2.assert_called_once()
        m3.assert_called_once()
        m4.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 15. Performance module __init__ exports
# ─────────────────────────────────────────────────────────────────────────────

class TestPerformancePackageExports:
    def test_async_scan_runner_importable(self):
        from apps.scanning.engine.performance import AsyncScanRunner
        assert AsyncScanRunner is not None

    def test_tester_result_importable(self):
        from apps.scanning.engine.performance import TesterResult
        assert TesterResult is not None

    def test_bounded_queue_importable(self):
        from apps.scanning.engine.performance import BoundedFindingsQueue
        assert BoundedFindingsQueue is not None

    def test_scan_memory_manager_importable(self):
        from apps.scanning.engine.performance import ScanMemoryManager
        assert ScanMemoryManager is not None

    def test_distributed_lock_importable(self):
        from apps.scanning.engine.performance import DistributedScanLock
        assert DistributedScanLock is not None

    def test_scaler_importable(self):
        from apps.scanning.engine.performance import WorkerAutoScaler
        assert WorkerAutoScaler is not None

    def test_partitioner_importable(self):
        from apps.scanning.engine.performance import ScanPartitioner
        assert ScanPartitioner is not None


# ─────────────────────────────────────────────────────────────────────────────
# 16. Registry (tester count and position)
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistration:
    def test_tester_count_is_87(self):
        from apps.scanning.engine.testers import get_all_testers
        assert len(get_all_testers()) == 87

    def test_last_tester_is_performance(self):
        from apps.scanning.engine.testers import get_all_testers
        from apps.scanning.engine.testers.performance_tester import PerformanceTester
        testers = get_all_testers()
        assert isinstance(testers[-2], PerformanceTester)

    def test_performance_tester_name_in_registry(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert 'Performance & Scale Engine' in names
