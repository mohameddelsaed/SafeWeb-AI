"""
Performance & Scale Tester — Phase 47.

Reports on performance-observable security characteristics of the target:
  * Response time baseline (slow responses → DoS vector, resource exhaustion)
  * Rate limiting presence (absent rate limits → brute-force / DoS risk)
  * Timing-based information leakage (valid-vs-404 response time delta)
  * Resource exhaustion signal on oversized input

These measurements also inform the :class:`AsyncScanRunner` and
:class:`ScaleController` to auto-tune scan concurrency and rate limits
for the current target.

TESTER_NAME: 'Performance & Scale Engine'
"""
from __future__ import annotations

import logging
import time

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Thresholds ────────────────────────────────────────────────────────────────
SLOW_THRESHOLD_MS: int = 3_000        # > 3 s  → "Slow Response"
VERY_SLOW_THRESHOLD_MS: int = 8_000   # > 8 s  → "Very Slow Response"
TIMING_DIFF_THRESHOLD_MS: int = 500   # > 500 ms delta → timing leak
RATE_LIMIT_CODES: frozenset = frozenset({429, 503, 509})

# Baseline samples to average for response-time measurement
BASELINE_SAMPLES: int = 3

# Size of the large-input probe (bytes)
LARGE_INPUT_SIZE: int = 10_000


class PerformanceTester(BaseTester):
    """Measures performance-security characteristics of the target.

    Checks (by depth):
      shallow  → response time baseline only
      medium   → + rate limit presence + timing leak
      deep     → + resource exhaustion signal

    All HTTP calls use ``_make_request`` (rate-limited, timeout-guarded).
    No destructive payloads are sent.
    """

    TESTER_NAME = 'Performance & Scale Engine'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        findings: list[dict] = []
        url = getattr(page, 'url', None) or (page.get('url', '') if isinstance(page, dict) else '')
        if not url:
            return findings

        findings.extend(self._test_response_time_baseline(url))

        if depth in ('medium', 'deep'):
            findings.extend(self._test_rate_limit_presence(url))
            findings.extend(self._test_timing_leak(url))

        if depth == 'deep':
            findings.extend(self._test_resource_exhaustion(url))

        return findings

    # ── Sub-tests ─────────────────────────────────────────────────────────────

    def _test_response_time_baseline(self, url: str) -> list:
        """Measure average response time over BASELINE_SAMPLES requests."""
        times_ms: list[float] = []
        for _ in range(BASELINE_SAMPLES):
            t0 = time.monotonic()
            resp = self._make_request('GET', url)
            elapsed = (time.monotonic() - t0) * 1000.0
            if resp is not None:
                times_ms.append(elapsed)

        if not times_ms:
            return []

        avg_ms = sum(times_ms) / len(times_ms)

        if avg_ms >= VERY_SLOW_THRESHOLD_MS:
            return [self._build_vuln(
                name='Extremely Slow Server Response Time',
                severity='medium',
                category='Performance',
                description=(
                    f'Average response time is {avg_ms:.0f} ms ({avg_ms / 1000:.1f} s), '
                    f'exceeding the {VERY_SLOW_THRESHOLD_MS} ms critical threshold. '
                    'Extremely slow responses may indicate server-side resource '
                    'exhaustion, unoptimised database queries, or an active DoS condition.'
                ),
                impact=(
                    'Severely slow responses degrade user experience and may signal '
                    'an exploitable resource exhaustion or denial-of-service condition.'
                ),
                remediation=(
                    'Profile the application with a performance profiler to identify '
                    'query/I-O bottlenecks.  Add database query caching, connection '
                    'pooling, CDN offloading, and response compression.'
                ),
                cwe='CWE-400',
                cvss=4.3,
                affected_url=url,
                evidence=(
                    f'Average: {avg_ms:.0f} ms over {len(times_ms)} samples. '
                    f'Samples: {[f"{t:.0f}ms" for t in times_ms]}'
                ),
            )]

        if avg_ms >= SLOW_THRESHOLD_MS:
            return [self._build_vuln(
                name='Slow Server Response Time',
                severity='low',
                category='Performance',
                description=(
                    f'Average response time is {avg_ms:.0f} ms, above the '
                    f'{SLOW_THRESHOLD_MS} ms threshold. '
                    'While not immediately critical, slow responses may indicate '
                    'inefficient backend operations.'
                ),
                impact=(
                    'Slow responses may indicate unoptimised queries or concurrency '
                    'issues that could be amplified under load.'
                ),
                remediation=(
                    'Profile the application and optimise slow database queries and '
                    'blocking I/O operations.'
                ),
                cwe='CWE-400',
                cvss=2.6,
                affected_url=url,
                evidence=f'Average: {avg_ms:.0f} ms over {len(times_ms)} samples.',
            )]

        return []

    def _test_rate_limit_presence(self, url: str) -> list:
        """Send a small burst (4 requests) and check for 429/503 responses.

        If no rate limiting is observed, report the missing control.
        Only reports for the *absence* of rate limiting as a security gap.
        """
        statuses: list[int] = []
        for _ in range(4):
            resp = self._make_request('GET', url)
            if resp is not None:
                statuses.append(resp.status_code)

        if not statuses:
            return []

        # Rate limiting is active — not a finding
        if any(s in RATE_LIMIT_CODES for s in statuses):
            return []

        # All 2xx — no rate limiting observed
        if all(200 <= s < 300 for s in statuses):
            return [self._build_vuln(
                name='No Rate Limiting Detected',
                severity='medium',
                category='Performance',
                description=(
                    f'Sent 4 rapid requests to {url} without triggering any rate '
                    'limiting (no 429/503 responses received).  Absence of rate '
                    'limiting exposes the endpoint to brute-force attacks, credential '
                    'stuffing, and denial-of-service.'
                ),
                impact=(
                    'Without rate limiting, attackers can brute-force credentials, '
                    'enumerate resources, exhaust server capacity, or abuse API quotas.'
                ),
                remediation=(
                    'Implement rate limiting at the application layer '
                    '(e.g. django-ratelimit, nginx limit_req_zone) and/or at the '
                    'CDN/WAF layer.  Return 429 Too Many Requests with a Retry-After '
                    'header when the limit is exceeded.'
                ),
                cwe='CWE-770',
                cvss=5.3,
                affected_url=url,
                evidence=f'Status codes from burst: {statuses}. No 429/503 observed.',
            )]

        return []

    def _test_timing_leak(self, url: str) -> list:
        """Compare response time for a valid URL vs a deliberately nonexistent path.

        A large time differential may enable timing-based resource enumeration.
        """
        t0 = time.monotonic()
        resp_valid = self._make_request('GET', url)
        t_valid_ms = (time.monotonic() - t0) * 1000.0

        probe_url = url.rstrip('/') + '/____timing_probe_xyzzy_phase47____'
        t0 = time.monotonic()
        resp_404 = self._make_request('GET', probe_url)
        t_404_ms = (time.monotonic() - t0) * 1000.0

        if resp_valid is None or resp_404 is None:
            return []

        diff_ms = abs(t_valid_ms - t_404_ms)
        if diff_ms >= TIMING_DIFF_THRESHOLD_MS:
            return [self._build_vuln(
                name='Response Time Discrepancy (Timing Information Leak)',
                severity='low',
                category='Performance',
                description=(
                    f'Response time for the valid URL ({t_valid_ms:.0f} ms) differs '
                    f'from a nonexistent path by {diff_ms:.0f} ms '
                    f'(nonexistent: {t_404_ms:.0f} ms).  Large timing differences '
                    'can enable timing-based enumeration of valid resources or users.'
                ),
                impact=(
                    'Attackers may enumerate valid paths, usernames, or data by '
                    'measuring response time differences.'
                ),
                remediation=(
                    'Ensure found/not-found responses return in approximately the '
                    'same time.  Use constant-time comparison for sensitive lookups.'
                ),
                cwe='CWE-208',
                cvss=3.1,
                affected_url=url,
                evidence=(
                    f'Valid: {t_valid_ms:.0f} ms, 404 probe: {t_404_ms:.0f} ms, '
                    f'delta: {diff_ms:.0f} ms (threshold: {TIMING_DIFF_THRESHOLD_MS} ms)'
                ),
            )]

        return []

    def _test_resource_exhaustion(self, url: str) -> list:
        """Send a request with a large parameter value (~10 KB).

        A 500 response with high latency indicates the server does not
        validate input size, making it vulnerable to resource exhaustion.
        """
        large_value = 'A' * LARGE_INPUT_SIZE
        t0 = time.monotonic()
        resp = self._make_request('GET', url, params={'q': large_value, 'input': large_value})
        elapsed_ms = (time.monotonic() - t0) * 1000.0

        if resp is None:
            return []

        if resp.status_code == 500 and elapsed_ms >= SLOW_THRESHOLD_MS:
            return [self._build_vuln(
                name='Resource Exhaustion on Oversized Input',
                severity='medium',
                category='Performance',
                description=(
                    f'Sending a {LARGE_INPUT_SIZE}-byte parameter caused an HTTP 500 '
                    f'response in {elapsed_ms:.0f} ms.  The server appears to perform '
                    'unbounded processing on large inputs, which can be exploited for '
                    'CPU/memory exhaustion.'
                ),
                impact=(
                    'Attackers can trigger application crashes or denial-of-service by '
                    'repeatedly sending oversized inputs.'
                ),
                remediation=(
                    'Enforce maximum input lengths at the framework or middleware level.  '
                    'Set maximum request body and query-string sizes in the web server '
                    'configuration (e.g. nginx client_max_body_size).  '
                    'Use streaming parsers for inputs that may legitimately be large.'
                ),
                cwe='CWE-400',
                cvss=5.3,
                affected_url=url,
                evidence=(
                    f'HTTP 500 with elapsed={elapsed_ms:.0f} ms for '
                    f'{LARGE_INPUT_SIZE}-byte input.  '
                    f'Snippet: {resp.text[:200] if resp.text else "(empty)"}'
                ),
            )]

        return []
