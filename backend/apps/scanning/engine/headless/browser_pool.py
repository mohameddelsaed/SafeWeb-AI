"""
Browser Pool — Phase 24.

Manages a pool of reusable Playwright browser contexts for
efficient headless crawling across multiple pages.

Features:
- Configurable pool size (3-5 contexts)
- Lifecycle: acquire / release contexts
- Automatic cleanup on shutdown
- Graceful fallback when Playwright is unavailable
"""
import logging
import threading
from queue import Queue, Empty
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright, Browser, BrowserContext, Playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.info('Playwright not installed — BrowserPool disabled')


class BrowserPool:
    """Thread-safe pool of Playwright browser contexts.

    Usage::

        pool = BrowserPool(pool_size=3)
        pool.start()
        ctx = pool.acquire()
        try:
            page = ctx.new_page()
            page.goto(url)
            ...
            page.close()
        finally:
            pool.release(ctx)
        pool.shutdown()
    """

    DEFAULT_POOL_SIZE = 3
    MAX_POOL_SIZE = 8

    # Browser launch args shared across instances
    BROWSER_ARGS = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-extensions',
        '--disable-background-networking',
    ]

    CONTEXT_OPTIONS = {
        'user_agent': 'SafeWeb AI Scanner/2.0 (Security Assessment Tool)',
        'ignore_https_errors': True,
        'viewport': {'width': 1280, 'height': 720},
        'java_script_enabled': True,
    }

    def __init__(self, pool_size: int = DEFAULT_POOL_SIZE,
                 context_options: Optional[dict] = None):
        """
        Args:
            pool_size: Number of browser contexts to pre-create (1-8).
            context_options: Extra Playwright context options to merge.
        """
        self._pool_size = max(1, min(pool_size, self.MAX_POOL_SIZE))
        self._extra_options = context_options or {}
        self._pool: Queue = Queue()
        self._all_contexts: list = []
        self._playwright: Optional['Playwright'] = None
        self._browser: Optional['Browser'] = None
        self._lock = threading.Lock()
        self._started = False
        self._shutdown = False

    @property
    def available(self) -> bool:
        """Whether the pool has been started and Playwright is available."""
        return HAS_PLAYWRIGHT and self._started and not self._shutdown

    @property
    def pool_size(self) -> int:
        return self._pool_size

    def start(self) -> bool:
        """Launch browser and create context pool.

        Returns:
            True if started successfully, False otherwise.
        """
        if not HAS_PLAYWRIGHT:
            logger.warning('BrowserPool: Playwright not available')
            return False

        with self._lock:
            if self._started:
                return True
            try:
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(
                    headless=True,
                    args=self.BROWSER_ARGS,
                )

                merged_opts = {**self.CONTEXT_OPTIONS, **self._extra_options}

                for _ in range(self._pool_size):
                    ctx = self._browser.new_context(**merged_opts)
                    self._all_contexts.append(ctx)
                    self._pool.put(ctx)

                self._started = True
                logger.info('BrowserPool: Started with %d contexts', self._pool_size)
                return True

            except Exception as e:
                logger.error('BrowserPool: Failed to start — %s', e)
                self._cleanup()
                return False

    def acquire(self, timeout: float = 30.0) -> Optional['BrowserContext']:
        """Acquire a browser context from the pool.

        Args:
            timeout: Max seconds to wait for a free context.

        Returns:
            BrowserContext or None if pool unavailable / timeout.
        """
        if not self.available:
            return None
        try:
            return self._pool.get(timeout=timeout)
        except Empty:
            logger.warning('BrowserPool: Acquire timed out after %.1fs', timeout)
            return None

    def release(self, ctx: 'BrowserContext') -> None:
        """Return a context to the pool.

        Clears cookies and closes all pages before returning.
        """
        if ctx is None or self._shutdown:
            return
        try:
            # Close all open pages to reset state
            for page in ctx.pages:
                try:
                    page.close()
                except Exception:
                    pass
            ctx.clear_cookies()
            self._pool.put(ctx)
        except Exception:
            # Context may be broken — don't return it
            logger.debug('BrowserPool: Failed to release context, discarding')

    def shutdown(self) -> None:
        """Close all contexts, browser, and Playwright."""
        with self._lock:
            self._shutdown = True
            self._cleanup()
            self._started = False
            logger.info('BrowserPool: Shutdown complete')

    def _cleanup(self) -> None:
        """Internal cleanup of all resources."""
        # Drain the queue
        while not self._pool.empty():
            try:
                self._pool.get_nowait()
            except Empty:
                break

        for ctx in self._all_contexts:
            try:
                ctx.close()
            except Exception:
                pass
        self._all_contexts.clear()

        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass

        try:
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass

        self._browser = None
        self._playwright = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.shutdown()

    def __del__(self):
        if self._started and not self._shutdown:
            try:
                self.shutdown()
            except Exception:
                pass
