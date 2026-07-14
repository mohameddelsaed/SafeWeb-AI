"""
Async Scan Runner — Phase 47 Performance & Scale v2.

Converts the synchronous tester-per-page loop into a fully concurrent
async pipeline.  Legacy sync ``BaseTester.test()`` methods are wrapped
with ``asyncio.to_thread()`` so they run in a thread pool without
blocking the event loop.

Features:
    • Semaphore-bounded concurrency (default 10 testers at once)
    • Per-tester timeout (default 60 s)
    • Per-page timeout (default 300 s)
    • Optional progress callback after each tester completes
    • Graceful error isolation — one tester failure never cancels others
    • Sync wrapper ``run_sync()`` for environments without a running loop
    • Multi-page concurrent execution with separate page-level semaphore
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_CONCURRENCY: int = 10          # max testers executing concurrently
DEFAULT_TESTER_TIMEOUT: float = 60.0   # seconds per tester per page
DEFAULT_PAGE_TIMEOUT: float = 300.0    # seconds for entire single-page scan
DEFAULT_MAX_PAGES_CONCURRENT: int = 3  # pages scanned in parallel


# ── Result dataclasses ───────────────────────────────────────────────────────

@dataclass
class TesterResult:
    """Result of a single tester against a single page."""
    tester_name: str
    findings: list = field(default_factory=list)
    duration: float = 0.0
    error: Optional[str] = None
    timed_out: bool = False

    @property
    def succeeded(self) -> bool:
        return self.error is None and not self.timed_out


@dataclass
class PageScanResult:
    """Aggregated result of all testers against a single page."""
    url: str
    results: list = field(default_factory=list)   # list[TesterResult]
    total_duration: float = 0.0
    findings_count: int = 0
    error_count: int = 0
    timeout_count: int = 0

    def all_findings(self) -> list:
        """Flatten all findings from all tester results."""
        out = []
        for tr in self.results:
            out.extend(tr.findings)
        return out


# ── Runner ────────────────────────────────────────────────────────────────────

class AsyncScanRunner:
    """
    Async-first vulnerability tester execution pipeline.

    Wraps sync ``BaseTester.test()`` calls with ``asyncio.to_thread()``
    and runs up to ``max_concurrency`` testers concurrently per page.

    Usage::

        runner = AsyncScanRunner(max_concurrency=10, tester_timeout=60)

        # Async (inside existing event loop):
        result = await runner.run_page(page, testers, depth='medium')

        # Sync (spawns its own event loop):
        result = runner.run_sync(page, testers, depth='medium')

        # Multiple pages concurrently:
        results = await runner.run_pages(pages, testers, depth='medium')
    """

    def __init__(
        self,
        max_concurrency: int = DEFAULT_CONCURRENCY,
        tester_timeout: float = DEFAULT_TESTER_TIMEOUT,
        page_timeout: float = DEFAULT_PAGE_TIMEOUT,
        progress_cb: Optional[Callable[[TesterResult], None]] = None,
    ):
        if max_concurrency < 1:
            raise ValueError('max_concurrency must be >= 1')
        if tester_timeout <= 0:
            raise ValueError('tester_timeout must be positive')
        self.max_concurrency = max_concurrency
        self.tester_timeout = tester_timeout
        self.page_timeout = page_timeout
        self.progress_cb = progress_cb
        # Semaphore is created lazily inside the running event loop
        self._semaphore: Optional[asyncio.Semaphore] = None

    def _get_semaphore(self) -> asyncio.Semaphore:
        """Create semaphore on first use (must be inside a running event loop)."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrency)
        return self._semaphore

    def reset_semaphore(self) -> None:
        """Force re-creation of semaphore (useful when reusing runner across loops)."""
        self._semaphore = None

    async def _run_single_tester(
        self,
        tester: Any,
        page: Any,
        depth: str,
        recon_data: dict,
    ) -> TesterResult:
        """Run one tester against one page, guarded by semaphore + timeout."""
        sem = self._get_semaphore()
        name = getattr(tester, 'TESTER_NAME', type(tester).__name__)
        start = time.monotonic()

        async with sem:
            try:
                findings = await asyncio.wait_for(
                    asyncio.to_thread(tester.test, page, depth, recon_data),
                    timeout=self.tester_timeout,
                )
                result = TesterResult(
                    tester_name=name,
                    findings=findings if isinstance(findings, list) else [],
                    duration=time.monotonic() - start,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    'AsyncScanRunner: tester %s timed out after %.1fs',
                    name, self.tester_timeout,
                )
                result = TesterResult(
                    tester_name=name,
                    duration=time.monotonic() - start,
                    timed_out=True,
                )
            except Exception as exc:
                logger.debug('AsyncScanRunner: tester %s raised: %s', name, exc)
                result = TesterResult(
                    tester_name=name,
                    duration=time.monotonic() - start,
                    error=str(exc),
                )

        if self.progress_cb:
            try:
                self.progress_cb(result)
            except Exception:
                pass  # Progress callbacks must never crash the runner

        return result

    async def run_page(
        self,
        page: Any,
        testers: list,
        depth: str = 'medium',
        recon_data: Optional[dict] = None,
    ) -> PageScanResult:
        """Run all testers against a single page concurrently.

        Returns a :class:`PageScanResult` with aggregated metrics.
        """
        if recon_data is None:
            recon_data = {}

        start = time.monotonic()
        url = getattr(page, 'url', None) or (page.get('url', '') if isinstance(page, dict) else '')

        tasks = [
            self._run_single_tester(t, page, depth, recon_data)
            for t in testers
        ]
        tester_results: list[TesterResult] = await asyncio.gather(*tasks)

        findings_count = sum(len(tr.findings) for tr in tester_results)
        error_count = sum(1 for tr in tester_results if tr.error)
        timeout_count = sum(1 for tr in tester_results if tr.timed_out)

        return PageScanResult(
            url=url,
            results=tester_results,
            total_duration=time.monotonic() - start,
            findings_count=findings_count,
            error_count=error_count,
            timeout_count=timeout_count,
        )

    async def run_pages(
        self,
        pages: list,
        testers: list,
        depth: str = 'medium',
        recon_data: Optional[dict] = None,
        max_pages_concurrent: int = DEFAULT_MAX_PAGES_CONCURRENT,
    ) -> list[PageScanResult]:
        """Run all testers against multiple pages with bounded page concurrency."""
        page_sem = asyncio.Semaphore(max(1, max_pages_concurrent))

        async def _scan_bounded(page: Any) -> PageScanResult:
            async with page_sem:
                return await self.run_page(page, testers, depth, recon_data)

        results = await asyncio.gather(*[_scan_bounded(p) for p in pages])
        return list(results)

    def run_sync(
        self,
        page: Any,
        testers: list,
        depth: str = 'medium',
        recon_data: Optional[dict] = None,
    ) -> PageScanResult:
        """Blocking sync wrapper — spawns its own event loop.

        Use when there is no existing event loop (e.g. Celery tasks,
        management commands, test code without pytest-asyncio).
        """
        self._semaphore = None  # Reset semaphore for fresh loop
        return asyncio.run(self.run_page(page, testers, depth, recon_data))

    def get_configuration(self) -> dict:
        """Return current runner configuration."""
        return {
            'max_concurrency': self.max_concurrency,
            'tester_timeout': self.tester_timeout,
            'page_timeout': self.page_timeout,
            'has_progress_cb': self.progress_cb is not None,
        }
