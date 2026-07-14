"""
Adaptive Rate Limiter — Per-host request throttling with backoff.

Tracks per-host request counts and response times, dynamically adjusting
delays to avoid being blocked or causing DoS. Integrates with both
sync ``requests`` and async ``aiohttp`` usage paths.

Features:
    • Per-host token-bucket rate limiting
    • Adaptive backoff on 429/503 responses
    • Configurable base delay, burst allowance, and ceiling
    • Thread-safe and asyncio-safe
"""
import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class HostState:
    """Mutable state for a single target host."""
    tokens: float = 10.0          # Current token count (burst allowance)
    max_tokens: float = 10.0      # Maximum burst capacity
    refill_rate: float = 2.0      # Tokens added per second
    last_refill: float = field(default_factory=time.monotonic)
    base_delay: float = 0.3       # Minimum inter-request delay (seconds)
    current_delay: float = 0.3    # Active delay (may increase on backoff)
    max_delay: float = 30.0       # Delay ceiling
    consecutive_errors: int = 0   # Track consecutive errors for backoff
    total_requests: int = 0
    total_errors: int = 0
    last_request: float = 0.0


class RateLimiter:
    """Per-host adaptive rate limiter.

    Usage (sync)::

        limiter = RateLimiter()
        await limiter.acquire("example.com")  # async
        limiter.acquire_sync("example.com")   # sync (blocking)

    After every response, call ``record_response`` to feed back status
    codes so the limiter can adapt.
    """

    def __init__(
        self,
        base_delay: float = 0.3,
        max_delay: float = 30.0,
        burst: int = 10,
        refill_rate: float = 2.0,
        global_rps: float = 0.0,
    ):
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._burst = burst
        self._refill_rate = refill_rate
        self._global_rps = global_rps  # 0 = unlimited
        self._hosts: dict[str, HostState] = {}
        self._lock = threading.Lock()
        self._async_locks: dict[str, asyncio.Lock] = {}
        self._paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()  # Initially not paused
        self._async_pause_event: Optional[asyncio.Event] = None
        self._global_last_request: float = 0.0
        self._global_lock = threading.Lock()

    # ── Internal ──────────────────────────────────────────────────────────

    def _get_host(self, host: str) -> HostState:
        if host not in self._hosts:
            self._hosts[host] = HostState(
                tokens=float(self._burst),
                max_tokens=float(self._burst),
                refill_rate=self._refill_rate,
                base_delay=self._base_delay,
                current_delay=self._base_delay,
                max_delay=self._max_delay,
            )
        return self._hosts[host]

    def _refill_tokens(self, state: HostState) -> None:
        now = time.monotonic()
        elapsed = now - state.last_refill
        state.tokens = min(state.max_tokens, state.tokens + elapsed * state.refill_rate)
        state.last_refill = now

    def _enforce_global_rps_sync(self) -> None:
        """Enforce global requests-per-second cap (sync)."""
        if self._global_rps <= 0:
            return
        with self._global_lock:
            now = time.monotonic()
            min_interval = 1.0 / self._global_rps
            elapsed = now - self._global_last_request
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._global_last_request = time.monotonic()

    async def _enforce_global_rps_async(self) -> None:
        """Enforce global requests-per-second cap (async)."""
        if self._global_rps <= 0:
            return
        now = time.monotonic()
        min_interval = 1.0 / self._global_rps
        elapsed = now - self._global_last_request
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._global_last_request = time.monotonic()

    # ── Pause / Resume ──────────────────────────────────────────────────────

    def pause(self) -> None:
        """Temporarily block all acquire() calls until resume() is called."""
        self._paused = True
        self._pause_event.clear()
        if self._async_pause_event is not None:
            self._async_pause_event.clear()

    def resume(self) -> None:
        """Resume all acquire() calls after a pause()."""
        self._paused = False
        self._pause_event.set()
        if self._async_pause_event is not None:
            self._async_pause_event.set()

    # ── Sync API (for ThreadPoolExecutor paths) ──────────────────────────

    def acquire_sync(self, host: str) -> None:
        """Block until a request slot is available for *host*."""
        self._pause_event.wait()  # Block if paused
        self._enforce_global_rps_sync()
        with self._lock:
            state = self._get_host(host)
            self._refill_tokens(state)

            # Wait if out of tokens
            if state.tokens < 1.0:
                wait = (1.0 - state.tokens) / state.refill_rate
                time.sleep(wait)
                self._refill_tokens(state)

            state.tokens -= 1.0

            # Enforce minimum inter-request delay
            elapsed_since_last = time.monotonic() - state.last_request
            if elapsed_since_last < state.current_delay:
                time.sleep(state.current_delay - elapsed_since_last)

            state.last_request = time.monotonic()
            state.total_requests += 1

    # ── Async API ────────────────────────────────────────────────────────

    async def acquire(self, host: str) -> None:
        """Await until a request slot is available for *host* (async)."""
        # Handle pause
        if self._paused:
            if self._async_pause_event is None:
                self._async_pause_event = asyncio.Event()
                if not self._paused:
                    self._async_pause_event.set()
            await self._async_pause_event.wait()

        await self._enforce_global_rps_async()

        # Per-host async lock prevents token race conditions
        if host not in self._async_locks:
            self._async_locks[host] = asyncio.Lock()

        async with self._async_locks[host]:
            state = self._get_host(host)
            self._refill_tokens(state)

            if state.tokens < 1.0:
                wait = (1.0 - state.tokens) / state.refill_rate
                await asyncio.sleep(wait)
                self._refill_tokens(state)

            state.tokens -= 1.0

            elapsed_since_last = time.monotonic() - state.last_request
            if elapsed_since_last < state.current_delay:
                await asyncio.sleep(state.current_delay - elapsed_since_last)

            state.last_request = time.monotonic()
            state.total_requests += 1

    # ── Feedback ─────────────────────────────────────────────────────────

    def record_response(self, host: str, status_code: int) -> None:
        """Adapt rate limits based on server response.

        • 429 / 503 → exponential backoff (×2 up to max_delay)
        • 2xx        → gradual recovery (×0.9 down to base_delay)
        • Other 5xx  → mild backoff (×1.3)
        """
        state = self._get_host(host)

        if status_code in (429, 503):
            state.consecutive_errors += 1
            state.current_delay = min(
                state.max_delay,
                state.current_delay * 2.0,
            )
            logger.debug(
                'Rate limiter backoff for %s → %.1fs (status %d)',
                host, state.current_delay, status_code,
            )
        elif 500 <= status_code < 600:
            state.consecutive_errors += 1
            state.current_delay = min(
                state.max_delay,
                state.current_delay * 1.3,
            )
        elif 200 <= status_code < 400:
            state.consecutive_errors = 0
            state.current_delay = max(
                state.base_delay,
                state.current_delay * 0.9,
            )
        state.total_errors += (1 if status_code >= 400 else 0)

    def record_error(self, host: str) -> None:
        """Record a connection-level error (timeout, DNS failure, etc.)."""
        state = self._get_host(host)
        state.consecutive_errors += 1
        state.total_errors += 1
        state.current_delay = min(
            state.max_delay,
            state.current_delay * 1.5,
        )

    # ── Introspection ────────────────────────────────────────────────────

    def get_stats(self, host: str) -> dict:
        """Return rate limiter stats for *host*."""
        state = self._get_host(host)
        return {
            'host': host,
            'current_delay': round(state.current_delay, 3),
            'tokens': round(state.tokens, 1),
            'total_requests': state.total_requests,
            'total_errors': state.total_errors,
            'consecutive_errors': state.consecutive_errors,
        }

    def get_all_stats(self) -> dict:
        """Return stats for all tracked hosts."""
        return {host: self.get_stats(host) for host in self._hosts}

    def reset(self, host: Optional[str] = None) -> None:
        """Reset limiter state for a host, or all hosts if *host* is None."""
        if host:
            self._hosts.pop(host, None)
            self._async_locks.pop(host, None)
        else:
            self._hosts.clear()
            self._async_locks.clear()
