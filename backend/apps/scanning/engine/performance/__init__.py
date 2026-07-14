"""
Performance & Scale Engine — Phase 47.

Provides three pillars of async, memory-safe, horizontally-scalable scanning:

  AsyncScanRunner       — Concurrent tester execution with asyncio + semaphore
  ScanMemoryManager     — Bounded findings queue + lazy payload loading + GC
  ScaleController       — Redis distributed locking, auto-scaling, partitioning
"""
from .async_scan_runner import (
    AsyncScanRunner,
    TesterResult,
    PageScanResult,
    DEFAULT_CONCURRENCY,
    DEFAULT_TESTER_TIMEOUT,
    DEFAULT_PAGE_TIMEOUT,
)
from .memory_manager import (
    BoundedFindingsQueue,
    LazyPayloadLoader,
    ScanMemoryManager,
    stream_wordlist,
    gc_between_phases,
    DEFAULT_QUEUE_CAPACITY,
    DEFAULT_FLUSH_THRESHOLD,
    WORDLIST_CHUNK_SIZE,
)
from .scale_controller import (
    DistributedScanLock,
    WorkerAutoScaler,
    ScanPartitioner,
    ScalingRecommendation,
    ScanPartition,
    DEFAULT_LOCK_TIMEOUT,
    DEFAULT_LOCK_ACQUIRE_TIMEOUT,
    DEFAULT_LOCK_POLL_INTERVAL,
    MIN_WORKERS,
    MAX_WORKERS,
    SCALE_UP_THRESHOLD,
    SCALE_DOWN_THRESHOLD,
    WORKER_QUEUE_RATIO,
)

__all__ = [
    'AsyncScanRunner', 'TesterResult', 'PageScanResult',
    'DEFAULT_CONCURRENCY', 'DEFAULT_TESTER_TIMEOUT', 'DEFAULT_PAGE_TIMEOUT',
    'BoundedFindingsQueue', 'LazyPayloadLoader', 'ScanMemoryManager',
    'stream_wordlist', 'gc_between_phases',
    'DEFAULT_QUEUE_CAPACITY', 'DEFAULT_FLUSH_THRESHOLD', 'WORDLIST_CHUNK_SIZE',
    'DistributedScanLock', 'WorkerAutoScaler', 'ScanPartitioner',
    'ScalingRecommendation', 'ScanPartition',
    'DEFAULT_LOCK_TIMEOUT', 'DEFAULT_LOCK_ACQUIRE_TIMEOUT', 'DEFAULT_LOCK_POLL_INTERVAL',
    'MIN_WORKERS', 'MAX_WORKERS',
    'SCALE_UP_THRESHOLD', 'SCALE_DOWN_THRESHOLD', 'WORKER_QUEUE_RATIO',
]
