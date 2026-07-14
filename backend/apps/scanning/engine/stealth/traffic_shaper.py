"""
Traffic Shaper — Phase 40: Rate Limit & Stealth Mode.

Per-host request throttling with:
  - Configurable RPS (1–100)
  - Random delay jitter (±30 % variance by default)
  - Burst control with cooldown periods
  - Automatic slowdown on 429 / 503 responses
  - HTTP / SOCKS5 proxy rotation
  - Tor SOCKS5 integration
"""
from __future__ import annotations

import asyncio
import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_RPS          = 10
MIN_RPS              = 1
MAX_RPS              = 100
DEFAULT_JITTER_PCT   = 0.30      # ±30 % of base delay
DEFAULT_BURST_LIMIT  = 5         # max rapid requests before cooldown
DEFAULT_COOLDOWN_SEC = 5.0       # cooldown duration after burst exhausted
SLOWDOWN_FACTOR_429  = 3.0       # delay multiplier on HTTP 429
SLOWDOWN_FACTOR_503  = 2.0       # delay multiplier on HTTP 503
RECOVERY_FACTOR      = 0.90      # delay reduction per batch of clean responses
CLEAN_THRESHOLD      = 5         # consecutive clean responses before recovery
TOR_SOCKS_DEFAULT_PORT = 9050


# ── Per-host state ────────────────────────────────────────────────────────────

@dataclass
class _HostBucket:
    """Mutable throttle state for a single target host."""

    rps: int = DEFAULT_RPS
    burst_limit: int = DEFAULT_BURST_LIMIT
    base_delay: float = field(init=False)
    current_delay: float = field(init=False)
    burst_remaining: int = field(init=False)
    cooldown_until: float = 0.0
    last_request: float = 0.0
    total_requests: int = 0
    consecutive_clean: int = 0

    def __post_init__(self) -> None:
        self.base_delay = 1.0 / max(1, self.rps)
        self.current_delay = self.base_delay
        self.burst_remaining = self.burst_limit


# ── TrafficShaper ─────────────────────────────────────────────────────────────

class TrafficShaper:
    """Central per-host traffic shaping controller.

    Usage (synchronous)::

        shaper = TrafficShaper(rps=5, jitter_pct=0.30)
        shaper.acquire("example.com")         # blocks as needed
        shaper.record_response("example.com", 429)

    Usage (asynchronous)::

        await shaper.async_acquire("example.com")

    Proxy / Tor::

        shaper.set_proxies(["http://proxy1:8080", "socks5://proxy2:1080"])
        shaper.enable_tor()
        proxy = shaper.get_proxy()   # returns next proxy URL
    """

    def __init__(
        self,
        rps: int = DEFAULT_RPS,
        jitter_pct: float = DEFAULT_JITTER_PCT,
        burst_limit: int = DEFAULT_BURST_LIMIT,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SEC,
        proxies: list[str] | None = None,
        tor: bool = False,
        tor_socks_port: int = TOR_SOCKS_DEFAULT_PORT,
    ) -> None:
        if not (MIN_RPS <= rps <= MAX_RPS):
            raise ValueError(
                f'rps must be between {MIN_RPS} and {MAX_RPS}, got {rps}'
            )
        if not (0.0 <= jitter_pct <= 1.0):
            raise ValueError(
                f'jitter_pct must be between 0.0 and 1.0, got {jitter_pct}'
            )

        self.rps = rps
        self.jitter_pct = jitter_pct
        self.burst_limit = burst_limit
        self.cooldown_seconds = cooldown_seconds

        self._hosts: dict[str, _HostBucket] = {}
        self._lock = threading.Lock()
        self._async_locks: dict[str, asyncio.Lock] = {}

        # Proxy state
        self._proxies: list[str] = list(proxies) if proxies else []
        self._proxy_index = 0
        self._proxy_lock = threading.Lock()

        # Tor
        self._tor_enabled = tor
        self._tor_socks_port = tor_socks_port

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_or_create(self, host: str) -> _HostBucket:
        """Return (or lazily create) the _HostBucket for *host*."""
        if host not in self._hosts:
            self._hosts[host] = _HostBucket(
                rps=self.rps,
                burst_limit=self.burst_limit,
            )
        return self._hosts[host]

    def _compute_delay(self, bucket: _HostBucket) -> float:
        """Return a jittered delay in seconds based on current bucket state."""
        delay = bucket.current_delay
        jitter = delay * self.jitter_pct
        return max(0.0, delay + random.uniform(-jitter, jitter))

    # ── Synchronous acquire ───────────────────────────────────────────────────

    def acquire(self, host: str) -> float:
        """Block until a request slot is available for *host*.

        Returns the actual sleep duration applied (seconds).
        """
        with self._lock:
            bucket = self._get_or_create(host)
            now = time.monotonic()

            if now < bucket.cooldown_until:
                # Still in burst cooldown — wait it out
                sleep_time = bucket.cooldown_until - now
                bucket.last_request = bucket.cooldown_until
                bucket.burst_remaining = bucket.burst_limit
            else:
                elapsed = now - bucket.last_request

                if elapsed < bucket.current_delay and bucket.burst_remaining > 0:
                    # Consume a burst token — no sleep this call
                    sleep_time = 0.0
                    bucket.burst_remaining -= 1
                    if bucket.burst_remaining == 0:
                        bucket.cooldown_until = now + self.cooldown_seconds
                else:
                    # Normal rate-limited delay
                    sleep_time = max(0.0, self._compute_delay(bucket) - elapsed)
                    bucket.burst_remaining = min(
                        bucket.burst_limit, bucket.burst_remaining + 1
                    )

                bucket.last_request = now + sleep_time

            bucket.total_requests += 1

        if sleep_time > 0:
            time.sleep(sleep_time)
        return sleep_time

    # ── Asynchronous acquire ──────────────────────────────────────────────────

    async def async_acquire(self, host: str) -> float:
        """Async equivalent of :meth:`acquire`.

        Returns the actual sleep duration applied (seconds).
        """
        if host not in self._async_locks:
            self._async_locks[host] = asyncio.Lock()

        async with self._async_locks[host]:
            with self._lock:
                bucket = self._get_or_create(host)
                now = time.monotonic()

                if now < bucket.cooldown_until:
                    sleep_time = bucket.cooldown_until - now
                    bucket.last_request = bucket.cooldown_until
                    bucket.burst_remaining = bucket.burst_limit
                else:
                    elapsed = now - bucket.last_request

                    if elapsed < bucket.current_delay and bucket.burst_remaining > 0:
                        sleep_time = 0.0
                        bucket.burst_remaining -= 1
                        if bucket.burst_remaining == 0:
                            bucket.cooldown_until = now + self.cooldown_seconds
                    else:
                        sleep_time = max(0.0, self._compute_delay(bucket) - elapsed)
                        bucket.burst_remaining = min(
                            bucket.burst_limit, bucket.burst_remaining + 1
                        )

                    bucket.last_request = now + sleep_time

                bucket.total_requests += 1

        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
        return sleep_time

    # ── Response feedback ─────────────────────────────────────────────────────

    def record_response(self, host: str, status_code: int) -> None:
        """Adapt delay for *host* based on the HTTP *status_code* received.

        - **429 Too Many Requests**: multiply delay by :data:`SLOWDOWN_FACTOR_429`
        - **503 Service Unavailable**: multiply delay by :data:`SLOWDOWN_FACTOR_503`
        - **2xx / 3xx / 4xx** (except 429): gradually recover toward base delay
        """
        with self._lock:
            bucket = self._get_or_create(host)

            if status_code == 429:
                bucket.current_delay = min(
                    bucket.current_delay * SLOWDOWN_FACTOR_429, 60.0
                )
                bucket.consecutive_clean = 0
                logger.debug(
                    '429 on %s — delay increased to %.2fs', host, bucket.current_delay
                )
            elif status_code == 503:
                bucket.current_delay = min(
                    bucket.current_delay * SLOWDOWN_FACTOR_503, 60.0
                )
                bucket.consecutive_clean = 0
                logger.debug(
                    '503 on %s — delay increased to %.2fs', host, bucket.current_delay
                )
            elif 200 <= status_code < 500:
                bucket.consecutive_clean += 1
                if bucket.consecutive_clean >= CLEAN_THRESHOLD:
                    bucket.current_delay = max(
                        bucket.base_delay,
                        bucket.current_delay * RECOVERY_FACTOR,
                    )
                    logger.debug(
                        'Recovery on %s — delay reduced to %.2fs',
                        host,
                        bucket.current_delay,
                    )

    # ── State management ──────────────────────────────────────────────────────

    def reset_host(self, host: str) -> None:
        """Clear per-host state (e.g., between successive scans)."""
        with self._lock:
            self._hosts.pop(host, None)

    def reset_all(self) -> None:
        """Clear all per-host state."""
        with self._lock:
            self._hosts.clear()

    def stats(self, host: str) -> dict:
        """Return current throttle stats for *host* as a plain dict."""
        with self._lock:
            bucket = self._hosts.get(host)
            if not bucket:
                return {'host': host, 'known': False}
            return {
                'host': host,
                'known': True,
                'rps': bucket.rps,
                'current_delay': bucket.current_delay,
                'base_delay': bucket.base_delay,
                'burst_remaining': bucket.burst_remaining,
                'total_requests': bucket.total_requests,
                'in_cooldown': time.monotonic() < bucket.cooldown_until,
            }

    # ── Proxy support ─────────────────────────────────────────────────────────

    def set_proxies(self, proxies: list[str]) -> None:
        """Replace the proxy pool with *proxies*."""
        with self._proxy_lock:
            self._proxies = list(proxies)
            self._proxy_index = 0

    def get_proxy(self, host: Optional[str] = None) -> Optional[str]:  # noqa: ARG002
        """Return the next proxy URL in round-robin rotation.

        Returns ``None`` when no proxies are configured and Tor is disabled.
        If Tor is enabled, returns ``socks5://127.0.0.1:<port>`` regardless
        of the configured proxy pool.
        """
        if self._tor_enabled:
            return f'socks5://127.0.0.1:{self._tor_socks_port}'
        with self._proxy_lock:
            if not self._proxies:
                return None
            proxy = self._proxies[self._proxy_index % len(self._proxies)]
            self._proxy_index += 1
            return proxy

    def enable_tor(self, socks_port: int = TOR_SOCKS_DEFAULT_PORT) -> None:
        """Route all traffic through the local Tor SOCKS5 proxy."""
        self._tor_enabled = True
        self._tor_socks_port = socks_port

    def disable_tor(self) -> None:
        """Disable Tor and return to direct / proxy-pool routing."""
        self._tor_enabled = False

    @property
    def proxy_count(self) -> int:
        """Number of proxies currently in the pool."""
        return len(self._proxies)

    @property
    def tor_enabled(self) -> bool:
        """True when Tor integration is active."""
        return self._tor_enabled
