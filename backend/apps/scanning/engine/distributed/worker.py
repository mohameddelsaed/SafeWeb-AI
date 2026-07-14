"""
Scan Worker — Phase 15 Distributed Scanning.

A ScanWorker executes a single ScanChunk dispatched by the ScanController.
Workers are instantiated inside Celery tasks; they are stateless except for
the chunk they are executing.
"""
import logging
import time
import traceback
from typing import Callable, Any

from .scan_controller import ScanChunk

logger = logging.getLogger(__name__)


class ScanWorker:
    """
    Executes a ScanChunk and reports progress back to a callback.

    Usage (inside a Celery task):
        worker = ScanWorker(chunk, progress_cb=self.update_state)
        result = worker.execute_chunk()
    """

    # Seconds between heartbeat log entries
    HEARTBEAT_INTERVAL = 30

    def __init__(self, chunk: ScanChunk, progress_cb: Callable | None = None):
        self.chunk = chunk
        self._progress_cb = progress_cb
        self._worker_id = f'worker-{chunk.chunk_id[:8]}'
        self._last_heartbeat = 0.0

    # ── Public API ────────────────────────────────

    def execute_chunk(self) -> dict[str, Any]:
        """
        Dispatch to the correct handler based on chunk_type.
        Returns a result dict suitable for ScanController.register_result().
        """
        self.chunk.status = 'running'
        self.report_progress(0.05)

        handlers = {
            'recon': self._handle_recon,
            'testing': self._handle_testing,
            'verification': self._handle_verification,
            'crawl': self._handle_crawl,
        }

        handler = handlers.get(self.chunk.chunk_type)
        if handler is None:
            raise ValueError(f'Unknown chunk type: {self.chunk.chunk_type}')

        try:
            result = handler()
            self.chunk.status = 'done'
            self.chunk.result = result
            self.report_progress(1.0)
            return result
        except Exception as exc:
            self.chunk.status = 'failed'
            self.chunk.error = str(exc)
            logger.error(f'[worker={self._worker_id}] Chunk {self.chunk.chunk_id} '
                         f'failed: {exc}\n{traceback.format_exc()}')
            raise

    def heartbeat(self, message: str = '') -> None:
        """Log a periodic heartbeat so orchestrator knows worker is alive."""
        now = time.time()
        if now - self._last_heartbeat >= self.HEARTBEAT_INTERVAL:
            self._last_heartbeat = now
            logger.info(f'[worker={self._worker_id}] Heartbeat — '
                        f'chunk={self.chunk.chunk_id[:8]} '
                        f'progress={self.chunk.progress:.0%} {message}')

    def report_progress(self, progress: float, meta: dict | None = None) -> None:
        """Update chunk progress and call the external callback if provided."""
        self.chunk.progress = max(0.0, min(1.0, progress))
        if self._progress_cb:
            try:
                self._progress_cb(
                    state='PROGRESS',
                    meta={
                        'progress': self.chunk.progress,
                        'chunk_id': self.chunk.chunk_id,
                        **(meta or {}),
                    },
                )
            except Exception:
                pass  # Never let callback failure crash the worker

    # ── Chunk handlers ────────────────────────────

    def _handle_recon(self) -> dict[str, Any]:
        """Run a single recon module against the target."""
        target = self.chunk.payload.get('target', '')
        module_name = self.chunk.payload.get('module', '')

        self.report_progress(0.1)
        self.heartbeat('starting recon')

        try:
            from apps.scanning.engine.recon import ReconEngine
            engine = ReconEngine(target)
            method = getattr(engine, f'run_{module_name}', None)
            if method is None:
                logger.warning(f'ReconEngine has no method run_{module_name}')
                return {'module': module_name, 'data': {}}
            data = method()
            self.report_progress(1.0)
            return {'module': module_name, 'data': data or {}}
        except Exception as exc:
            logger.warning(f'Recon module {module_name} failed: {exc}')
            return {'module': module_name, 'data': {}, 'error': str(exc)}

    def _handle_testing(self) -> dict[str, Any]:
        """Run enabled testers against a bucket of URLs."""
        urls: list[str] = self.chunk.payload.get('urls', [])
        tester_names: list[str] = self.chunk.payload.get('testers', [])

        if not urls:
            return {'vulnerabilities': []}

        vulnerabilities: list[dict] = []
        total = len(urls)

        for i, url in enumerate(urls):
            self.report_progress(0.1 + 0.8 * (i / total))
            self.heartbeat(f'testing url {i + 1}/{total}')

            for tname in tester_names:
                try:
                    from apps.scanning.engine.testers import get_tester
                    tester_cls = get_tester(tname)
                    if tester_cls is None:
                        continue
                    tester = tester_cls(url)
                    results = tester.run()
                    if results:
                        vulnerabilities.extend(
                            r if isinstance(r, dict) else vars(r)
                            for r in results
                        )
                except Exception as exc:
                    logger.warning(f'Tester {tname} failed on {url}: {exc}')

        self.report_progress(1.0)
        return {'vulnerabilities': vulnerabilities}

    def _handle_verification(self) -> dict[str, Any]:
        """Re-verify a set of vulnerability findings."""
        vulns: list[dict] = self.chunk.payload.get('vulnerabilities', [])
        depth: str = self.chunk.payload.get('depth', 'standard')

        self.report_progress(0.1)
        try:
            import asyncio
            from apps.scanning.engine.verification_engine import VerificationEngine
            engine = VerificationEngine()
            results = asyncio.run(engine.verify_all(vulns, depth))
            self.report_progress(1.0)
            return {'verification_results': [vars(r) for r in results]}
        except Exception as exc:
            logger.warning(f'Verification chunk failed: {exc}')
            return {'verification_results': []}

    def _handle_crawl(self) -> dict[str, Any]:
        """Crawl a sub-set of discovered URLs (used for deep crawl distribution)."""
        base_url: str = self.chunk.payload.get('base_url', '')
        seed_urls: list[str] = self.chunk.payload.get('seed_urls', [])
        depth: str = self.chunk.payload.get('depth', 'shallow')

        self.report_progress(0.1)
        try:
            from apps.scanning.engine.crawler import WebCrawler
            crawler = WebCrawler(base_url, depth=depth)
            # Seed with provided URLs so crawler explores from them
            crawler.visited.update(seed_urls)
            pages = crawler.crawl()
            self.report_progress(1.0)
            return {'pages': [vars(p) for p in pages]}
        except Exception as exc:
            logger.warning(f'Crawl chunk failed: {exc}')
            return {'pages': []}
