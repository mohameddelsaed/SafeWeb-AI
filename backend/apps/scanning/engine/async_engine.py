"""
Async Engine — Replaces ThreadPoolExecutor with asyncio-native concurrency.

Provides ``AsyncTaskRunner`` which can run a mix of native async coroutines
and legacy sync functions in parallel, with configurable concurrency limits,
per-task timeouts, progress callbacks, and graceful cancellation.

The orchestrator uses this to run recon waves, tester batches, and
analyzer phases concurrently.

Features:
    • Semaphore-bounded asyncio.gather for async tasks
    • asyncio.to_thread() wrapping for legacy sync functions
    • Per-task timeout enforcement
    • Progress callback after each task completes
    • Graceful cancellation on critical failure
    • Structured result collection (key → result/error)
"""
import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    TIMEOUT = 'timeout'
    CANCELLED = 'cancelled'


@dataclass
class TaskResult:
    """Result of a single task execution."""
    key: str
    status: TaskStatus
    result: Any = None
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class TaskSpec:
    """Specification for a task to be executed.

    Args:
        key:        Unique identifier for the task (e.g. 'dns', 'whois').
        fn:         Callable — either an async coroutine function or a sync function.
        args:       Positional arguments.
        kwargs:     Keyword arguments.
        timeout:    Per-task timeout in seconds (0 = no timeout).
        critical:   If True, failure cancels remaining tasks.
        priority:   Task priority (0 = highest, 10 = lowest). Lower runs first.
        depends_on: List of task keys that must complete successfully first.
    """
    key: str
    fn: Callable
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    timeout: float = 120.0
    critical: bool = False
    priority: int = 5
    depends_on: list = field(default_factory=list)


class AsyncTaskRunner:
    """Execute heterogeneous tasks concurrently with bounded parallelism.

    Usage::

        runner = AsyncTaskRunner(max_concurrency=10)
        runner.add('dns', run_dns_recon, args=(target, depth))
        runner.add('whois', run_whois_recon, args=(target,))
        results = await runner.run()
        # results == {'dns': TaskResult(...), 'whois': TaskResult(...)}
    """

    def __init__(
        self,
        max_concurrency: int = 100,
        default_timeout: float = 120.0,
        on_progress: Optional[Callable[[TaskResult], None]] = None,
        cancel_on_critical: bool = True,
        memory_guard_mb: int = 500,
    ):
        self._max_concurrency = max_concurrency
        self._default_timeout = default_timeout
        self._on_progress = on_progress
        self._cancel_on_critical = cancel_on_critical
        self._memory_guard_mb = memory_guard_mb
        self._tasks: list[TaskSpec] = []
        self._results: dict[str, TaskResult] = {}
        self._cancelled = False
        self._pending_results_count = 0

    def add(
        self,
        key: str,
        fn: Callable,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        timeout: Optional[float] = None,
        critical: bool = False,
    ) -> 'AsyncTaskRunner':
        """Add a task to the runner. Returns self for chaining."""
        self._tasks.append(TaskSpec(
            key=key,
            fn=fn,
            args=args,
            kwargs=kwargs or {},
            timeout=timeout if timeout is not None else self._default_timeout,
            critical=critical,
        ))
        return self

    def add_batch(self, tasks: dict[str, tuple]) -> 'AsyncTaskRunner':
        """Add multiple tasks at once.

        Args:
            tasks: Dict of ``{key: (fn, args, kwargs)}`` triples.
                   ``kwargs`` can be omitted (defaults to ``{}``).
        """
        for key, spec in tasks.items():
            fn = spec[0]
            args = spec[1] if len(spec) > 1 else ()
            kwargs = spec[2] if len(spec) > 2 else {}
            self.add(key, fn, args=args, kwargs=kwargs)
        return self

    async def run(self) -> dict[str, TaskResult]:
        """Execute all queued tasks and return results keyed by task key."""
        sem = asyncio.Semaphore(self._max_concurrency)
        cancel_event = asyncio.Event()

        async def _exec(spec: TaskSpec) -> TaskResult:
            if self._cancelled or cancel_event.is_set():
                return TaskResult(key=spec.key, status=TaskStatus.CANCELLED)

            # Memory guard: pause if results buffer is too large
            if self._memory_guard_mb > 0:
                try:
                    import sys
                    results_size_mb = sys.getsizeof(self._results) / (1024 * 1024)
                    if results_size_mb > self._memory_guard_mb:
                        logger.warning('Memory guard triggered (%.1f MB) — pausing new tasks', results_size_mb)
                        await asyncio.sleep(1.0)
                except Exception:
                    pass

            # Check dependencies — skip if any required task failed
            for dep_key in spec.depends_on:
                dep_result = self._results.get(dep_key)
                if dep_result and dep_result.status in (TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED):
                    task_result = TaskResult(
                        key=spec.key,
                        status=TaskStatus.FAILED,
                        error=f'Dependency [{dep_key}] failed',
                    )
                    self._results[spec.key] = task_result
                    return task_result

            async with sem:
                start = time.monotonic()
                try:
                    # Detect if fn is a coroutine function → call directly
                    # Otherwise → wrap in asyncio.to_thread for sync functions
                    if asyncio.iscoroutinefunction(spec.fn):
                        coro = spec.fn(*spec.args, **spec.kwargs)
                    else:
                        coro = asyncio.to_thread(spec.fn, *spec.args, **spec.kwargs)

                    if spec.timeout > 0:
                        result = await asyncio.wait_for(coro, timeout=spec.timeout)
                    else:
                        result = await coro

                    elapsed = time.monotonic() - start
                    task_result = TaskResult(
                        key=spec.key,
                        status=TaskStatus.COMPLETED,
                        result=result,
                        duration=elapsed,
                    )

                except asyncio.TimeoutError:
                    elapsed = time.monotonic() - start
                    task_result = TaskResult(
                        key=spec.key,
                        status=TaskStatus.TIMEOUT,
                        error=f'Task timed out after {spec.timeout}s',
                        duration=elapsed,
                    )
                    logger.warning('Task [%s] timed out after %.1fs', spec.key, spec.timeout)

                except asyncio.CancelledError:
                    task_result = TaskResult(
                        key=spec.key,
                        status=TaskStatus.CANCELLED,
                        duration=time.monotonic() - start,
                    )

                except Exception as e:
                    elapsed = time.monotonic() - start
                    task_result = TaskResult(
                        key=spec.key,
                        status=TaskStatus.FAILED,
                        error=str(e),
                        duration=elapsed,
                    )
                    logger.warning('Task [%s] failed: %s', spec.key, e)

                    if spec.critical and self._cancel_on_critical:
                        logger.error('Critical task [%s] failed — cancelling remaining tasks', spec.key)
                        cancel_event.set()

                self._results[spec.key] = task_result

                if self._on_progress:
                    try:
                        self._on_progress(task_result)
                    except Exception:
                        pass  # Don't let callback errors affect execution

                return task_result

        # Launch all tasks via gather (sorted by priority, dependencies checked)
        sorted_tasks = sorted(self._tasks, key=lambda t: t.priority)
        aws = [_exec(spec) for spec in sorted_tasks]
        await asyncio.gather(*aws, return_exceptions=True)

        return self._results

    def cancel(self) -> None:
        """Signal cancellation of remaining tasks."""
        self._cancelled = True

    @property
    def completed_count(self) -> int:
        return sum(1 for r in self._results.values() if r.status == TaskStatus.COMPLETED)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self._results.values() if r.status in (TaskStatus.FAILED, TaskStatus.TIMEOUT))

    @property
    def summary(self) -> dict:
        """Return a summary of execution results."""
        statuses = {}
        for r in self._results.values():
            statuses[r.status.value] = statuses.get(r.status.value, 0) + 1
        total_duration = sum(r.duration for r in self._results.values())
        return {
            'total_tasks': len(self._tasks),
            'statuses': statuses,
            'total_duration': round(total_duration, 3),
            'results': {k: {'status': v.status.value, 'duration': round(v.duration, 3)}
                        for k, v in self._results.items()},
        }


# ── Convenience functions ─────────────────────────────────────────────────

async def run_parallel(
    tasks: dict[str, tuple],
    max_concurrency: int = 10,
    default_timeout: float = 120.0,
    on_progress: Optional[Callable] = None,
) -> dict[str, Any]:
    """Convenience function to run tasks and return {key: result} dict.

    Failed/timed-out tasks will have value ``None``.

    Args:
        tasks: Dict of ``{key: (fn, args, kwargs)}`` triples.
        max_concurrency: Max parallel tasks.
        default_timeout: Per-task timeout.
        on_progress: Callback after each task completes.

    Returns:
        Dict mapping task keys to their results (None on failure).
    """
    runner = AsyncTaskRunner(
        max_concurrency=max_concurrency,
        default_timeout=default_timeout,
        on_progress=on_progress,
    )
    runner.add_batch(tasks)
    results = await runner.run()
    return {
        key: tr.result if tr.status == TaskStatus.COMPLETED else None
        for key, tr in results.items()
    }


async def run_pipeline(
    stages: list[list[TaskSpec]],
    max_concurrency: int = 10,
    default_timeout: float = 120.0,
) -> dict[str, TaskResult]:
    """Execute stages sequentially, tasks within each stage in parallel.

    Args:
        stages: List of stages, each stage is a list of TaskSpec objects.
        max_concurrency: Max parallel tasks within each stage.
        default_timeout: Per-task timeout.

    Returns:
        Combined dict of all task results across all stages.
    """
    all_results: dict[str, TaskResult] = {}
    for stage in stages:
        runner = AsyncTaskRunner(
            max_concurrency=max_concurrency,
            default_timeout=default_timeout,
        )
        for spec in stage:
            runner.add(
                spec.key, spec.fn,
                args=spec.args, kwargs=spec.kwargs,
                timeout=spec.timeout, critical=spec.critical,
            )
        stage_results = await runner.run()
        all_results.update(stage_results)
    return all_results
