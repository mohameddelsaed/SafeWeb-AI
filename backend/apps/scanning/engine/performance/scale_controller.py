"""
Scale Controller — Phase 47 Performance & Scale v2.

Three horizontal-scaling primitives:

  DistributedScanLock
      Redis SET NX EX distributed lock — prevents two Celery workers from
      running the same scan_id concurrently.  Only the lock owner (identified
      by a unique caller token) can release or extend it.

  WorkerAutoScaler
      Recommends Celery worker counts based on current queue depth.
      Does NOT spawn workers directly; produces :class:`ScalingRecommendation`
      objects for the orchestrator to act on.

  ScanPartitioner
      Splits a URL list evenly across N workers using either round-robin or
      consistent hash bucketing.  Returns :class:`ScanPartition` objects
      ready to be dispatched as Celery sub-tasks.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_LOCK_TIMEOUT: int = 3600          # seconds a lock may be held
DEFAULT_LOCK_ACQUIRE_TIMEOUT: float = 30.0  # seconds to wait when blocking
DEFAULT_LOCK_POLL_INTERVAL: float = 2.0   # seconds between retry attempts

MIN_WORKERS: int = 1
MAX_WORKERS: int = 20
SCALE_UP_THRESHOLD: int = 50    # queue depth that triggers a scale-up suggestion
SCALE_DOWN_THRESHOLD: int = 5   # queue depth that triggers a scale-down suggestion
WORKER_QUEUE_RATIO: int = 10    # one worker per N queued tasks (for compute)


# ── DistributedScanLock ───────────────────────────────────────────────────────

class DistributedScanLock:
    """Redis-based distributed lock for scan deduplication.

    Uses ``SET key value NX EX ttl`` (atomic test-and-set with expiry) so
    there is no SETNX + EXPIRE race condition.

    The lock *value* is a unique caller token; only the process that set it
    can release or extend it — other processes cannot steal the lock.

    The ``redis_client`` argument accepts any object that implements:
      * ``set(key, value, nx=True, ex=seconds) → truthy/falsy``
      * ``get(key) → bytes | str | None``
      * ``delete(key)``
      * ``expire(key, seconds)``

    This interface is satisfied by `redis.Redis`, `fakeredis.FakeRedis`,
    and any plain dict-backed mock used in tests.

    Usage::

        lock = DistributedScanLock(redis_client, scan_id=42)
        if lock.acquire():
            try:
                run_scan()
            finally:
                lock.release()

        # As context manager (blocking acquire):
        with DistributedScanLock(redis_client, scan_id=42) as acquired:
            if acquired:
                run_scan()
    """

    LOCK_PREFIX = 'safeweb:scan_lock:'

    def __init__(
        self,
        redis_client: Any,
        scan_id: int,
        lock_timeout: int = DEFAULT_LOCK_TIMEOUT,
        acquire_timeout: float = DEFAULT_LOCK_ACQUIRE_TIMEOUT,
        poll_interval: float = DEFAULT_LOCK_POLL_INTERVAL,
    ):
        self._redis = redis_client
        self.scan_id = scan_id
        self.lock_timeout = lock_timeout
        self.acquire_timeout = acquire_timeout
        self.poll_interval = poll_interval
        self._lock_key = f'{self.LOCK_PREFIX}{scan_id}'
        # Unique value so only this instance can release the lock
        self._lock_value = f'{scan_id}:{id(self)}:{time.monotonic()}'
        self._acquired = False

    def acquire(self, blocking: bool = True) -> bool:
        """Try to acquire the lock.

        Args:
            blocking: If True, retries until ``acquire_timeout`` expires.
                      If False, makes exactly one attempt.

        Returns:
            True if the lock was acquired, False otherwise.
        """
        deadline = time.monotonic() + (self.acquire_timeout if blocking else 0.0)

        while True:
            result = self._redis.set(
                self._lock_key,
                self._lock_value,
                nx=True,
                ex=self.lock_timeout,
            )
            if result:
                self._acquired = True
                logger.info('DistributedScanLock: acquired for scan %d', self.scan_id)
                return True

            if not blocking or time.monotonic() >= deadline:
                logger.debug(
                    'DistributedScanLock: could not acquire for scan %d', self.scan_id,
                )
                return False

            time.sleep(self.poll_interval)

    def release(self) -> bool:
        """Release the lock.  Only succeeds if this instance owns it.

        Returns:
            True if released, False if we don't own it or it expired.
        """
        if not self._acquired:
            return False

        current = self._redis.get(self._lock_key)
        if isinstance(current, bytes):
            current = current.decode()

        if current == self._lock_value:
            self._redis.delete(self._lock_key)
            self._acquired = False
            logger.info('DistributedScanLock: released for scan %d', self.scan_id)
            return True

        # Lock expired or was taken by another process
        self._acquired = False
        return False

    def extend(self, additional_seconds: int) -> bool:
        """Extend the lock TTL if we still own it.

        Returns:
            True if extended, False if we no longer own the lock.
        """
        current = self._redis.get(self._lock_key)
        if isinstance(current, bytes):
            current = current.decode()
        if current == self._lock_value:
            self._redis.expire(self._lock_key, self.lock_timeout + additional_seconds)
            return True
        return False

    def is_locked(self) -> bool:
        """Return True if ANY process currently holds this lock."""
        return self._redis.get(self._lock_key) is not None

    @property
    def acquired(self) -> bool:
        """True if this instance currently holds the lock."""
        return self._acquired

    def __enter__(self) -> bool:
        self.acquire(blocking=True)
        return self._acquired

    def __exit__(self, *_args: Any) -> None:
        if self._acquired:
            self.release()


# ── ScalingRecommendation ─────────────────────────────────────────────────────

@dataclass
class ScalingRecommendation:
    """Output of :class:`WorkerAutoScaler.assess`."""
    queue_depth: int
    current_workers: int
    recommended_workers: int
    action: str          # 'scale_up' | 'scale_down' | 'maintain'
    reason: str
    urgency: str = 'low'  # 'low' | 'medium' | 'high'


# ── WorkerAutoScaler ──────────────────────────────────────────────────────────

class WorkerAutoScaler:
    """Recommends Celery worker counts based on queue depth.

    Does **not** spawn or terminate workers directly — that is
    infrastructure-specific.  Consumers should inspect the returned
    :class:`ScalingRecommendation` and provision workers accordingly.

    Usage::

        scaler = WorkerAutoScaler()
        rec = scaler.assess(queue_depth=75, current_workers=4)
        if rec.action == 'scale_up':
            add_workers(rec.recommended_workers - rec.current_workers)
    """

    def __init__(
        self,
        min_workers: int = MIN_WORKERS,
        max_workers: int = MAX_WORKERS,
        scale_up_threshold: int = SCALE_UP_THRESHOLD,
        scale_down_threshold: int = SCALE_DOWN_THRESHOLD,
        worker_queue_ratio: int = WORKER_QUEUE_RATIO,
    ):
        if min_workers < 1:
            raise ValueError('min_workers must be >= 1')
        if max_workers < min_workers:
            raise ValueError('max_workers must be >= min_workers')
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_up_threshold = scale_up_threshold
        self.scale_down_threshold = scale_down_threshold
        self.worker_queue_ratio = worker_queue_ratio

    def assess(self, queue_depth: int, current_workers: int) -> ScalingRecommendation:
        """Produce a :class:`ScalingRecommendation` for the given state.

        Args:
            queue_depth:     Number of pending tasks in the Celery queue.
            current_workers: Number of currently active workers.

        Returns:
            A :class:`ScalingRecommendation` with ``action`` set to
            ``'scale_up'``, ``'scale_down'``, or ``'maintain'``.
        """
        if queue_depth < 0:
            raise ValueError('queue_depth must be non-negative')
        current_workers = max(self.min_workers, current_workers)

        if queue_depth >= self.scale_up_threshold:
            recommended = min(
                self.max_workers,
                max(self.min_workers, queue_depth // self.worker_queue_ratio + 1),
            )
            if recommended > current_workers:
                urgency = 'high' if queue_depth >= self.scale_up_threshold * 2 else 'medium'
                return ScalingRecommendation(
                    queue_depth=queue_depth,
                    current_workers=current_workers,
                    recommended_workers=recommended,
                    action='scale_up',
                    reason=(
                        f'Queue depth {queue_depth} ≥ scale-up threshold '
                        f'{self.scale_up_threshold}'
                    ),
                    urgency=urgency,
                )

        if queue_depth <= self.scale_down_threshold and current_workers > self.min_workers:
            return ScalingRecommendation(
                queue_depth=queue_depth,
                current_workers=current_workers,
                recommended_workers=self.min_workers,
                action='scale_down',
                reason=(
                    f'Queue depth {queue_depth} ≤ scale-down threshold '
                    f'{self.scale_down_threshold}'
                ),
                urgency='low',
            )

        return ScalingRecommendation(
            queue_depth=queue_depth,
            current_workers=current_workers,
            recommended_workers=current_workers,
            action='maintain',
            reason='Queue depth within normal operating range',
            urgency='low',
        )

    def get_configuration(self) -> dict:
        """Return the current scaler configuration as a plain dict."""
        return {
            'min_workers': self.min_workers,
            'max_workers': self.max_workers,
            'scale_up_threshold': self.scale_up_threshold,
            'scale_down_threshold': self.scale_down_threshold,
            'worker_queue_ratio': self.worker_queue_ratio,
        }


# ── ScanPartition ─────────────────────────────────────────────────────────────

@dataclass
class ScanPartition:
    """A slice of URLs assigned to one Celery worker."""
    partition_id: int
    worker_index: int
    total_workers: int
    urls: list
    scan_id: int = 0
    metadata: dict = field(default_factory=dict)

    @property
    def size(self) -> int:
        """Number of URLs in this partition."""
        return len(self.urls)


# ── ScanPartitioner ───────────────────────────────────────────────────────────

class ScanPartitioner:
    """Distributes a URL list across N workers for parallel execution.

    Strategies:
      ``'round_robin'``  — URL[i] goes to worker[i % N].
                           Guarantees equal-sized partitions (±1 URL).
      ``'hash_bucket'``  — URL is hashed to a bucket deterministically.
                           The same URL always maps to the same worker,
                           which enables cross-worker deduplication.

    Usage::

        partitioner = ScanPartitioner(num_workers=4)
        partitions = partitioner.partition(urls, scan_id=123)
        for p in partitions:
            dispatch_to_worker.delay(p.worker_index, p.urls)
    """

    STRATEGIES = ('round_robin', 'hash_bucket')

    def __init__(
        self,
        num_workers: int,
        strategy: str = 'round_robin',
    ):
        if num_workers < 1:
            raise ValueError('num_workers must be >= 1')
        if strategy not in self.STRATEGIES:
            raise ValueError(f'strategy must be one of {self.STRATEGIES}')
        self.num_workers = num_workers
        self.strategy = strategy

    def partition(self, urls: list, scan_id: int = 0) -> list[ScanPartition]:
        """Partition ``urls`` across :attr:`num_workers` workers.

        Returns a list of :class:`ScanPartition` objects (one per worker),
        including workers that received an empty slice.
        """
        buckets: list[list] = [[] for _ in range(self.num_workers)]

        if self.strategy == 'round_robin':
            for i, url in enumerate(urls):
                buckets[i % self.num_workers].append(url)
        else:  # hash_bucket
            for url in urls:
                idx = int(hashlib.md5(str(url).encode()).hexdigest(), 16) % self.num_workers
                buckets[idx].append(url)

        return [
            ScanPartition(
                partition_id=i,
                worker_index=i,
                total_workers=self.num_workers,
                urls=buckets[i],
                scan_id=scan_id,
            )
            for i in range(self.num_workers)
        ]

    def rebalance(self, partitions: list[ScanPartition]) -> list[ScanPartition]:
        """Re-distribute all URLs from existing partitions evenly.

        Useful when some partitions ran faster than others and remaining
        work should be redistributed to idle workers.
        """
        if not partitions:
            return []
        all_urls = [url for p in partitions for url in p.urls]
        scan_id = partitions[0].scan_id if partitions else 0
        return self.partition(all_urls, scan_id=scan_id)

    def stats(self, partitions: list[ScanPartition]) -> dict:
        """Return load-balance statistics for a set of partitions."""
        if not partitions:
            return {
                'total_urls': 0,
                'num_partitions': 0,
                'min_size': 0,
                'max_size': 0,
                'avg_size': 0.0,
                'balance_ratio': 1.0,
            }
        sizes = [p.size for p in partitions]
        max_s = max(sizes)
        return {
            'total_urls': sum(sizes),
            'num_partitions': len(partitions),
            'min_size': min(sizes),
            'max_size': max_s,
            'avg_size': sum(sizes) / len(sizes),
            'balance_ratio': min(sizes) / max_s if max_s > 0 else 1.0,
        }
