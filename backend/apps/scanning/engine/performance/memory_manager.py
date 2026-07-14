"""
Memory Manager — Phase 47 Performance & Scale v2.

Prevents out-of-memory conditions during large scans by providing:

  BoundedFindingsQueue  — Thread-safe fixed-capacity deque that auto-flushes
                           to persistent storage when the high-water mark is hit.
  LazyPayloadLoader     — LRU-cached, on-demand payload module loader so payload
                           libraries are only imported when a tester actually needs them.
  ScanMemoryManager     — Context-managed facade that combines the above with
                           explicit GC calls between scan phases.
  stream_wordlist()     — Generator that yields wordlist lines in chunks so the
                           full file is never loaded into memory at once.
  gc_between_phases()   — Force Python GC across all three generations and return
                           collection statistics.
"""
from __future__ import annotations

import gc
import logging
import threading
from collections import deque
from typing import Any, Callable, Generator, Optional

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_QUEUE_CAPACITY: int = 500       # max findings in memory before auto-flush
DEFAULT_FLUSH_THRESHOLD: float = 0.80  # flush when 80 % of capacity used
DEFAULT_MAX_CACHED_PAYLOADS: int = 20  # max payload modules in LRU cache
WORDLIST_CHUNK_SIZE: int = 100         # lines per chunk yielded by stream_wordlist


# ── BoundedFindingsQueue ──────────────────────────────────────────────────────

class BoundedFindingsQueue:
    """Thread-safe, bounded queue for scan findings.

    When the number of queued findings reaches
    ``floor(capacity * flush_threshold)`` the queue calls ``flush_fn``
    (if supplied) to drain findings to persistent storage.

    If ``flush_fn`` raises, the flushed items are restored and the flush
    count is not incremented so nothing is silently lost.

    Usage::

        def save(items): Vulnerability.objects.bulk_create(...)

        bq = BoundedFindingsQueue(capacity=500, flush_fn=save)
        bq.put({'name': 'XSS', ...})   # auto-flushes at 80 % of 500
        remaining = bq.drain()         # clear without calling flush_fn
        bq.flush()                     # force flush to flush_fn
    """

    def __init__(
        self,
        capacity: int = DEFAULT_QUEUE_CAPACITY,
        flush_fn: Optional[Callable[[list], None]] = None,
        flush_threshold: float = DEFAULT_FLUSH_THRESHOLD,
    ):
        if capacity < 1:
            raise ValueError('capacity must be >= 1')
        if not (0.0 < flush_threshold <= 1.0):
            raise ValueError('flush_threshold must be in (0.0, 1.0]')
        self.capacity = capacity
        self.flush_threshold = flush_threshold
        self._flush_fn = flush_fn
        self._items: deque = deque()
        self._lock = threading.Lock()
        self._flush_count = 0
        self._total_put = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def put(self, finding: dict) -> None:
        """Enqueue a finding. Auto-flushes when the high-water mark is hit."""
        with self._lock:
            self._items.append(finding)
            self._total_put += 1
            if len(self._items) >= max(1, int(self.capacity * self.flush_threshold)):
                self._flush_locked()

    def flush(self) -> int:
        """Force-flush all queued findings to ``flush_fn``. Returns item count."""
        with self._lock:
            return self._flush_locked()

    def drain(self) -> list:
        """Remove and return all items without calling ``flush_fn``."""
        with self._lock:
            items = list(self._items)
            self._items.clear()
            return items

    def size(self) -> int:
        """Number of findings currently queued."""
        with self._lock:
            return len(self._items)

    def is_full(self) -> bool:
        """True when the queue has reached or exceeded capacity."""
        return self.size() >= self.capacity

    def stats(self) -> dict:
        """Return current queue statistics."""
        size = self.size()
        return {
            'size': size,
            'capacity': self.capacity,
            'flush_count': self._flush_count,
            'total_put': self._total_put,
            'utilization': size / self.capacity,
        }

    # ── Internal ───────────────────────────────────────────────────────────

    def _flush_locked(self) -> int:
        """Flush under the held lock. Restores items if flush_fn raises."""
        if not self._items:
            return 0
        items = list(self._items)
        self._items.clear()
        if self._flush_fn:
            try:
                self._flush_fn(items)
            except Exception as exc:
                logger.warning('BoundedFindingsQueue: flush_fn raised: %s — restoring items', exc)
                self._items.extendleft(reversed(items))
                return 0
        self._flush_count += 1
        return len(items)


# ── LazyPayloadLoader ─────────────────────────────────────────────────────────

class LazyPayloadLoader:
    """LRU-cached, on-demand payload module loader.

    Payload libraries are only imported when a tester explicitly requests
    them; the least-recently-used entry is evicted when the cache is full.

    Usage::

        loader = LazyPayloadLoader(max_cached=20)

        # Load on demand, cached on subsequent calls:
        payloads = loader.get('sqli', lambda: load_sqli_payloads())

        loader.evict('sqli')    # release one entry
        loader.evict_all()      # release everything
    """

    def __init__(self, max_cached: int = DEFAULT_MAX_CACHED_PAYLOADS):
        if max_cached < 1:
            raise ValueError('max_cached must be >= 1')
        self.max_cached = max_cached
        self._cache: dict[str, Any] = {}
        self._access_order: deque = deque()   # front = LRU, back = MRU
        self._lock = threading.Lock()
        self._load_count = 0
        self._cache_hits = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def get(self, key: str, loader_fn: Callable[[], Any]) -> Any:
        """Return cached entry for ``key``, loading via ``loader_fn`` if missing."""
        with self._lock:
            if key in self._cache:
                self._cache_hits += 1
                self._touch(key)
                return self._cache[key]

            if len(self._cache) >= self.max_cached:
                self._evict_lru_locked()

            data = loader_fn()
            self._cache[key] = data
            self._access_order.append(key)
            self._load_count += 1
            return data

    def evict(self, key: str) -> bool:
        """Evict a single key. Returns True if the key existed."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                try:
                    self._access_order.remove(key)
                except ValueError:
                    pass
                return True
            return False

    def evict_all(self) -> int:
        """Evict everything. Returns the count of evicted entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._access_order.clear()
            return count

    def stats(self) -> dict:
        """Return loader statistics."""
        total_accesses = self._load_count + self._cache_hits
        return {
            'cached': len(self._cache),
            'max_cached': self.max_cached,
            'load_count': self._load_count,
            'cache_hits': self._cache_hits,
            'hit_rate': self._cache_hits / total_accesses if total_accesses else 0.0,
        }

    # ── Internal ───────────────────────────────────────────────────────────

    def _touch(self, key: str) -> None:
        """Move key to MRU position (must be called under lock)."""
        try:
            self._access_order.remove(key)
        except ValueError:
            pass
        self._access_order.append(key)

    def _evict_lru_locked(self) -> None:
        """Evict the LRU entry (must be called under lock)."""
        if self._access_order:
            lru_key = self._access_order.popleft()
            self._cache.pop(lru_key, None)


# ── Helpers ───────────────────────────────────────────────────────────────────

def stream_wordlist(
    path: str,
    chunk_size: int = WORDLIST_CHUNK_SIZE,
) -> Generator[list[str], None, None]:
    """Yield wordlist entries in chunks of ``chunk_size``.

    Comment lines (starting with ``#``) and blank lines are skipped.
    Yields are Python lists so callers can iterate or bulk-pass them.

    If the file does not exist a warning is logged and the generator
    returns immediately without yielding anything.

    Usage::

        for chunk in stream_wordlist('/path/to/wordlist.txt', chunk_size=200):
            for word in chunk:
                probe(word)
    """
    chunk: list[str] = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                chunk.append(line)
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
        if chunk:
            yield chunk
    except FileNotFoundError:
        logger.warning('stream_wordlist: file not found: %s', path)
        return
    except OSError as exc:
        logger.warning('stream_wordlist: error reading %s: %s', path, exc)
        return


def gc_between_phases(log: bool = True) -> dict:
    """Force Python garbage collection across all three generations.

    Returns a dict with per-generation collection counts and totals.
    Safe to call on any thread.

    Usage::

        stats = gc_between_phases()
        print(stats['total_collected'])
    """
    count_before = sum(gc.get_count())
    gen0 = gc.collect(0)
    gen1 = gc.collect(1)
    gen2 = gc.collect(2)
    count_after = sum(gc.get_count())

    stats = {
        'collected_gen0': gen0,
        'collected_gen1': gen1,
        'collected_gen2': gen2,
        'total_collected': gen0 + gen1 + gen2,
        'count_before': count_before,
        'count_after': count_after,
    }
    if log:
        logger.debug(
            'gc_between_phases: collected=%d objects (gen0=%d gen1=%d gen2=%d)',
            stats['total_collected'], gen0, gen1, gen2,
        )
    return stats


# ── ScanMemoryManager ─────────────────────────────────────────────────────────

class ScanMemoryManager:
    """Context-managed façade for all memory safety features.

    Combines:
      - :class:`BoundedFindingsQueue` for finding buffering
      - :class:`LazyPayloadLoader` for on-demand payloads
      - :func:`gc_between_phases` for inter-phase cleanup

    Usage::

        def save_to_db(findings):
            Vulnerability.objects.bulk_create([Vulnerability(**f) for f in findings])

        with ScanMemoryManager(queue_capacity=500, flush_fn=save_to_db) as mem:
            mem.findings.put({'name': 'XSS', ...})
            sqli_payloads = mem.payloads.get('sqli', load_sqli)
            mem.gc_phase()    # call between recon / testing / reporting phases
        # __exit__ flushes remaining findings, evicts all payloads, runs gc.collect()
    """

    def __init__(
        self,
        queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
        flush_fn: Optional[Callable[[list], None]] = None,
        max_cached_payloads: int = DEFAULT_MAX_CACHED_PAYLOADS,
    ):
        self.findings = BoundedFindingsQueue(
            capacity=queue_capacity,
            flush_fn=flush_fn,
        )
        self.payloads = LazyPayloadLoader(max_cached=max_cached_payloads)
        self._phase_count = 0
        self._gc_stats: list[dict] = []

    def gc_phase(self) -> dict:
        """Force GC and record stats. Call once between each scan phase."""
        self._phase_count += 1
        stats = gc_between_phases(log=True)
        self._gc_stats.append(stats)
        return stats

    def summary(self) -> dict:
        """Return full memory management summary dict for reporting."""
        return {
            'findings_stats': self.findings.stats(),
            'payload_stats': self.payloads.stats(),
            'phases_gc': self._phase_count,
            'total_gc_collected': sum(s['total_collected'] for s in self._gc_stats),
        }

    def __enter__(self) -> 'ScanMemoryManager':
        return self

    def __exit__(self, *_args: Any) -> None:
        self.findings.flush()
        self.payloads.evict_all()
        gc.collect()
