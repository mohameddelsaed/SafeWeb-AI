"""
Async HTTP Client — Shared aiohttp session with connection pooling,
automatic retries, rate limiting, and response caching.

Provides both async and sync-compatible APIs so existing synchronous
recon modules can migrate incrementally.  New modules should use the
async ``request()`` method directly.

Features:
    • Persistent aiohttp.ClientSession with TCPConnector pooling (500 total, 50/host)
    • Per-host adaptive rate limiting (via RateLimiter)
    • Automatic retry with exponential backoff (configurable)
    • Response deduplication cache (URL → body/headers/status)
    • Sync wrapper via ``request_sync()`` for gradual migration
    • Custom User-Agent rotation
    • SSL verification disabled (required for security scanning)
    • stream_get() for large response streaming
    • uvloop support where available
"""
import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientTimeout, TCPConnector, ClientSession

from .rate_limiter import RateLimiter

# ── uvloop support ──────────────────────────────────────────────────────────
try:
    import uvloop
    uvloop.install()
    _UVLOOP_AVAILABLE = True
except ImportError:
    _UVLOOP_AVAILABLE = False  # Fall back to standard asyncio

logger = logging.getLogger(__name__)

# ── User-Agent Rotation ──────────────────────────────────────────────────────

_USER_AGENTS = [
    'SafeWeb AI Scanner/2.0 (Security Assessment)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]


@dataclass
class HttpResponse:
    """Lightweight response wrapper matching common response attributes."""
    url: str
    status_code: int
    headers: dict
    text: str
    content: bytes
    elapsed: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def json(self) -> Any:
        import json
        return json.loads(self.text)


class AsyncHttpClient:
    """Shared async HTTP client with connection pooling and rate limiting.

    Usage::

        async with AsyncHttpClient() as client:
            resp = await client.request('GET', 'https://example.com')
            print(resp.status_code, resp.text[:200])

    Or as a long-lived instance::

        client = AsyncHttpClient()
        await client.start()
        resp = await client.request('GET', url)
        await client.close()
    """

    def __init__(
        self,
        max_connections: int = 500,
        max_per_host: int = 50,
        timeout: float = 15.0,
        max_retries: int = 3,
        retry_statuses: tuple = (429, 500, 502, 503, 504),
        rate_limiter: Optional[RateLimiter] = None,
        rotate_user_agent: bool = True,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
        proxy: Optional[str] = None,
    ):
        self._max_connections = max_connections
        self._max_per_host = max_per_host
        self._timeout = ClientTimeout(total=timeout, connect=10.0)
        self._max_retries = max_retries
        self._retry_statuses = set(retry_statuses)
        self._rate_limiter = rate_limiter or RateLimiter()
        self._rotate_ua = rotate_user_agent
        self._follow_redirects = follow_redirects
        self._verify_ssl = verify_ssl
        self._proxy = proxy
        self._session: Optional[ClientSession] = None
        self._ua_index = 0
        self._request_count = 0
        self._cache: dict[str, HttpResponse] = {}
        self._cache_enabled = True

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> 'AsyncHttpClient':
        """Create the underlying aiohttp session."""
        if self._session is None or self._session.closed:
            connector = TCPConnector(
                limit=self._max_connections,
                limit_per_host=self._max_per_host,
                ssl=self._verify_ssl,
                ttl_dns_cache=300,        # 5-min DNS cache
                enable_cleanup_closed=True,
            )
            self._session = ClientSession(
                connector=connector,
                timeout=self._timeout,
                headers=self._default_headers(),
            )
        return self

    async def close(self) -> None:
        """Close the aiohttp session and release connections."""
        if self._session and not self._session.closed:
            await self._session.close()
        self._cache.clear()

    async def __aenter__(self) -> 'AsyncHttpClient':
        return await self.start()

    async def __aexit__(self, *exc) -> None:
        await self.close()

    # ── Core Request ─────────────────────────────────────────────────────

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict] = None,
        data: Any = None,
        json: Any = None,
        params: Optional[dict] = None,
        allow_redirects: Optional[bool] = None,
        timeout: Optional[float] = None,
        use_cache: bool = True,
        **kwargs,
    ) -> HttpResponse:
        """Make an HTTP request with retries and rate limiting.

        Args:
            method:           HTTP method (GET, POST, etc.).
            url:              Full URL to request.
            headers:          Extra headers (merged on top of defaults).
            data:             Form data body.
            json:             JSON body.
            params:           Query string parameters.
            allow_redirects:  Override instance-level redirect setting.
            timeout:          Override instance-level timeout (seconds).
            use_cache:        Whether to check/populate the response cache.
            **kwargs:         Passed through to aiohttp.

        Returns:
            HttpResponse with status_code, headers, text, content.
        """
        if self._session is None or self._session.closed:
            await self.start()

        # Cache check (GET only)
        cache_key = None
        if use_cache and self._cache_enabled and method.upper() == 'GET':
            cache_key = self._cache_key(method, url, params)
            if cache_key in self._cache:
                return self._cache[cache_key]

        host = urlparse(url).hostname or ''
        if allow_redirects is None:
            allow_redirects = self._follow_redirects

        req_timeout = ClientTimeout(total=timeout) if timeout else None
        merged_headers = self._request_headers(headers)

        last_error: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                await self._rate_limiter.acquire(host)
                start = time.monotonic()

                async with self._session.request(
                    method,
                    url,
                    headers=merged_headers,
                    data=data,
                    json=json,
                    params=params,
                    allow_redirects=allow_redirects,
                    timeout=req_timeout,
                    ssl=self._verify_ssl,
                    proxy=self._proxy,
                    **kwargs,
                ) as resp:
                    body = await resp.read()
                    text = body.decode('utf-8', errors='replace')
                    elapsed = time.monotonic() - start

                    self._rate_limiter.record_response(host, resp.status)
                    self._request_count += 1

                    response = HttpResponse(
                        url=str(resp.url),
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        text=text,
                        content=body,
                        elapsed=elapsed,
                    )

                    # Retry on retryable status codes
                    if resp.status in self._retry_statuses and attempt < self._max_retries:
                        backoff = min(2 ** attempt, 30)
                        logger.debug(
                            'Retryable status %d for %s, attempt %d/%d, backoff %.1fs',
                            resp.status, url, attempt, self._max_retries, backoff,
                        )
                        await asyncio.sleep(backoff)
                        continue

                    # Cache successful GET responses
                    if cache_key and 200 <= resp.status < 400:
                        self._cache[cache_key] = response

                    return response

            except asyncio.TimeoutError:
                last_error = TimeoutError(f'Request timed out: {method} {url}')
                self._rate_limiter.record_error(host)
                logger.debug('Timeout %s %s (attempt %d/%d)', method, url, attempt, self._max_retries)
            except aiohttp.ClientError as e:
                last_error = e
                self._rate_limiter.record_error(host)
                logger.debug('Client error %s %s: %s (attempt %d/%d)', method, url, e, attempt, self._max_retries)
            except Exception as e:
                last_error = e
                self._rate_limiter.record_error(host)
                logger.debug('Unexpected error %s %s: %s', method, url, e)
                break  # Don't retry unexpected errors

            if attempt < self._max_retries:
                await asyncio.sleep(min(2 ** attempt, 30))

        # All retries exhausted — return error response
        return HttpResponse(
            url=url,
            status_code=0,
            headers={},
            text='',
            content=b'',
            error=str(last_error) if last_error else 'Request failed',
        )

    async def stream_get(self, url: str, chunk_callback, chunk_size: int = 65536, **kwargs) -> 'HttpResponse':
        """Stream a large GET response, calling chunk_callback(bytes) for each chunk.

        Args:
            url:            URL to fetch.
            chunk_callback: Callable(chunk: bytes) called for each data chunk.
            chunk_size:     Bytes per chunk (default 64 KB).
            **kwargs:       Passed through to aiohttp session.

        Returns:
            HttpResponse with text/content empty (data streamed via callback).
        """
        if self._session is None or self._session.closed:
            await self.start()

        host = urlparse(url).hostname or ''
        await self._rate_limiter.acquire(host)
        start = time.monotonic()

        try:
            async with self._session.get(url, ssl=self._verify_ssl, **kwargs) as resp:
                async for chunk in resp.content.iter_chunked(chunk_size):
                    chunk_callback(chunk)
                elapsed = time.monotonic() - start
                return HttpResponse(
                    url=str(resp.url),
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    text='[streamed]',
                    content=b'[streamed]',
                    elapsed=elapsed,
                )
        except Exception as exc:
            return HttpResponse(
                url=url, status_code=0, headers={}, text='', content=b'',
                error=str(exc),
            )

    # ── Convenience Methods ──────────────────────────────────────────────

    async def get(self, url: str, **kwargs) -> HttpResponse:
        """Shorthand for ``request('GET', url, ...)``."""
        return await self.request('GET', url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        """Shorthand for ``request('POST', url, ...)``."""
        return await self.request('POST', url, **kwargs)

    async def head(self, url: str, **kwargs) -> HttpResponse:
        """Shorthand for ``request('HEAD', url, ...)``."""
        return await self.request('HEAD', url, **kwargs)

    async def put(self, url: str, **kwargs) -> HttpResponse:
        """Shorthand for ``request('PUT', url, ...)``."""
        return await self.request('PUT', url, **kwargs)

    async def options(self, url: str, **kwargs) -> HttpResponse:
        """Shorthand for ``request('OPTIONS', url, ...)``."""
        return await self.request('OPTIONS', url, **kwargs)

    # ── Batch Requests ───────────────────────────────────────────────────
    async def batch_get(
        self,
        urls: list[str],
        max_concurrency: int = 50,
        **kwargs,
    ) -> list[HttpResponse]:
        """Concurrently GET a list of URLs with bounded concurrency.

        Args:
            urls: List of URLs to fetch.
            max_concurrency: Max simultaneous requests (default 50).
            **kwargs: Passed through to request().

        Returns:
            List of HttpResponse in the same order as *urls*.
        """
        sem = asyncio.Semaphore(max_concurrency)

        async def _fetch(url: str) -> HttpResponse:
            async with sem:
                return await self.get(url, **kwargs)

        return await asyncio.gather(*[_fetch(u) for u in urls])
    async def gather(
        self,
        requests_list: list[dict],
        max_concurrency: int = 20,
    ) -> list[HttpResponse]:
        """Execute multiple requests concurrently with a semaphore.

        Args:
            requests_list: List of dicts with keys: method, url, [headers, data, params, ...]
            max_concurrency: Max simultaneous requests.

        Returns:
            List of HttpResponse in the same order as *requests_list*.
        """
        sem = asyncio.Semaphore(max_concurrency)

        async def _limited(req: dict) -> HttpResponse:
            async with sem:
                method = req.pop('method', 'GET')
                url = req.pop('url')
                return await self.request(method, url, **req)

        tasks = [_limited(dict(r)) for r in requests_list]
        return await asyncio.gather(*tasks)

    # ── Sync Wrapper (for gradual migration) ─────────────────────────────

    def request_sync(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> HttpResponse:
        """Synchronous wrapper around the async ``request()``.

        Designed for existing sync recon modules that haven't been
        converted to async yet. Creates/reuses an event loop.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Already inside an async context — use nest_asyncio or thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self.request(method, url, **kwargs))
                return future.result()
        else:
            return asyncio.run(self._request_sync_inner(method, url, **kwargs))

    async def _request_sync_inner(self, method: str, url: str, **kwargs) -> HttpResponse:
        async with AsyncHttpClient(
            rate_limiter=self._rate_limiter,
            max_connections=self._max_connections,
            max_per_host=self._max_per_host,
        ) as client:
            return await client.request(method, url, **kwargs)

    # ── Internal Helpers ─────────────────────────────────────────────────

    def _default_headers(self) -> dict:
        return {
            'User-Agent': _USER_AGENTS[0],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        }

    def _request_headers(self, extra: Optional[dict] = None) -> dict:
        hdrs = {}
        if self._rotate_ua:
            self._ua_index = (self._ua_index + 1) % len(_USER_AGENTS)
            hdrs['User-Agent'] = _USER_AGENTS[self._ua_index]
        if extra:
            hdrs.update(extra)
        return hdrs

    @staticmethod
    def _cache_key(method: str, url: str, params: Optional[dict]) -> str:
        raw = f'{method}:{url}:{sorted(params.items()) if params else ""}'
        return hashlib.md5(raw.encode()).hexdigest()

    # ── Stats ────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        return {
            'total_requests': self._request_count,
            'cache_size': len(self._cache),
            'rate_limiter': self._rate_limiter.get_all_stats(),
        }
