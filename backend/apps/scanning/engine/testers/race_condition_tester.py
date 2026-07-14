"""
RaceConditionTester — Race Condition / TOCTOU detection.
OWASP A04:2021 — Insecure Design.

Tests for: concurrent request vulnerabilities in financial transactions,
coupon redemption, voting, and state-changing operations.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Form actions that suggest state-changing operations
RACE_SENSITIVE_KEYWORDS = [
    'transfer', 'payment', 'pay', 'checkout', 'purchase', 'buy',
    'redeem', 'coupon', 'voucher', 'discount', 'promo',
    'vote', 'like', 'upvote', 'downvote', 'rate',
    'withdraw', 'deposit', 'send', 'balance',
    'delete', 'remove', 'cancel', 'update', 'edit',
    'register', 'signup', 'subscribe', 'claim', 'reward',
]


class RaceConditionTester(BaseTester):
    """Test for race condition / TOCTOU vulnerabilities."""

    TESTER_NAME = 'Race Condition'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Only test forms that perform state-changing operations
        for form in page.forms:
            if form.method.upper() != 'POST':
                continue

            if not self._is_race_sensitive(form, page.url):
                continue

            vuln = self._test_race_condition(form, page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # Dual-session cross-account race (medium/deep)
        if self.has_victim_session and depth in ('medium', 'deep'):
            for form in page.forms:
                if form.method.upper() != 'POST':
                    continue
                if not self._is_race_sensitive(form, page.url):
                    continue
                vuln = self._test_cross_account_race(form, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # Test for limit bypass (deep)
        if depth == 'deep':
            for form in page.forms:
                if form.method.upper() != 'POST':
                    continue
                vuln = self._test_limit_bypass(form, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_race_sensitive(self, form, page_url):
        """Check if a form likely performs a race-sensitive operation."""
        action = (form.action or page_url).lower()
        for keyword in RACE_SENSITIVE_KEYWORDS:
            if keyword in action:
                return True

        # Check field names
        for inp in form.inputs:
            name = (inp.name or '').lower()
            for keyword in RACE_SENSITIVE_KEYWORDS:
                if keyword in name:
                    return True
        return False

    def _test_race_condition(self, form, page_url):
        """Send concurrent requests to detect race conditions."""
        target_url = form.action or page_url
        data = {}
        for inp in form.inputs:
            if inp.name:
                data[inp.name] = inp.value or 'test'

        concurrent_count = 10
        results = []

        def send_request():
            return self._make_request('POST', target_url, data=data)

        try:
            with ThreadPoolExecutor(max_workers=concurrent_count) as executor:
                futures = [executor.submit(send_request) for _ in range(concurrent_count)]
                for future in as_completed(futures, timeout=15):
                    try:
                        resp = future.result()
                        if resp:
                            results.append(resp.status_code)
                    except Exception:
                        pass
        except Exception:
            return None

        if not results:
            return None

        # Analyze results: if all requests succeeded (200/302), potential race
        success_codes = [c for c in results if c in (200, 201, 302, 303)]
        if len(success_codes) >= concurrent_count * 0.8:
            return self._build_vuln(
                name=f'Potential Race Condition: {target_url}',
                severity='high',
                category='Race Condition',
                description=f'{len(success_codes)}/{concurrent_count} concurrent duplicate POST '
                           f'requests were all accepted, suggesting the endpoint lacks proper '
                           f'concurrency controls.',
                impact='Attackers can exploit race conditions to perform double-spending, '
                      'redeem coupons multiple times, bypass rate limits, or corrupt data.',
                remediation='Use database-level locks (SELECT FOR UPDATE), unique constraints, '
                           'idempotency keys, or optimistic locking. '
                           'Implement proper transaction isolation levels.',
                cwe='CWE-362',
                cvss=7.5,
                affected_url=target_url,
                evidence=f'{len(success_codes)}/{concurrent_count} concurrent requests returned success.',
            )
        return None

    def _test_limit_bypass(self, form, page_url):
        """Test if rate limits can be bypassed via concurrent requests."""
        target_url = form.action or page_url

        # First, check if there's a rate limit normally
        data = {}
        for inp in form.inputs:
            if inp.name:
                data[inp.name] = inp.value or 'test'

        # Send 5 sequential requests
        sequential_blocked = False
        for _ in range(5):
            resp = self._make_request('POST', target_url, data=data)
            if resp and resp.status_code == 429:
                sequential_blocked = True
                break

        if not sequential_blocked:
            return None  # No rate limit to bypass

        # Now try 5 concurrent requests to bypass the limit
        time.sleep(2)  # wait for rate limit to reset

        results = []

        def send_request():
            return self._make_request('POST', target_url, data=data)

        try:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(send_request) for _ in range(5)]
                for future in as_completed(futures, timeout=10):
                    try:
                        resp = future.result()
                        if resp:
                            results.append(resp.status_code)
                    except Exception:
                        pass
        except Exception:
            return None

        # If concurrent requests bypass the rate limit
        success = sum(1 for c in results if c in (200, 201, 302))
        if success >= 4:
            return self._build_vuln(
                name=f'Rate Limit Bypass via Concurrency: {target_url}',
                severity='medium',
                category='Race Condition',
                description='Rate limiting can be bypassed by sending concurrent requests. '
                           'Sequential requests trigger the limit, but parallel requests succeed.',
                impact='Attackers can bypass rate limits for brute force, spam, or abuse.',
                remediation='Implement server-side rate limiting with atomic counters '
                           '(e.g., Redis INCR). Use distributed rate limiters.',
                cwe='CWE-362',
                cvss=5.3,
                affected_url=target_url,
                evidence=f'Sequential: blocked at 429. Concurrent: {success}/5 succeeded.',
            )
        return None

    def _test_cross_account_race(self, form, page_url):
        """Test for cross-account race conditions using dual sessions.

        Attacker and victim fire the same state-changing request simultaneously.
        If both succeed, the operation lacks proper locking per user.
        """
        target_url = form.action or page_url
        data = {}
        for inp in form.inputs:
            if inp.name:
                data[inp.name] = inp.value or 'test'

        attacker_results = []
        victim_results = []

        def send_attacker():
            return self._make_request('POST', target_url, data=data)

        def send_victim():
            return self._make_victim_request('POST', target_url, data=data)

        try:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for _ in range(5):
                    futures.append(('attacker', executor.submit(send_attacker)))
                    futures.append(('victim', executor.submit(send_victim)))

                for role, future in futures:
                    try:
                        resp = future.result(timeout=15)
                        if resp:
                            bucket = attacker_results if role == 'attacker' else victim_results
                            bucket.append(resp.status_code)
                    except Exception:
                        pass
        except Exception:
            return None

        a_success = sum(1 for c in attacker_results if c in (200, 201, 302, 303))
        v_success = sum(1 for c in victim_results if c in (200, 201, 302, 303))

        if a_success >= 3 and v_success >= 3:
            return self._build_vuln(
                name=f'Cross-Account Race Condition: {target_url}',
                severity='high',
                category='Race Condition',
                description=f'Concurrent requests from two different user sessions both succeed '
                           f'({a_success} attacker + {v_success} victim out of 5 each). '
                           f'The operation lacks per-user or per-resource locking.',
                impact='Attackers can exploit cross-account race conditions for double-spending, '
                      'balance manipulation, or data corruption across user boundaries.',
                remediation='Use database-level locks scoped to the user or resource. '
                           'Implement distributed locks (e.g., Redis) for cross-service operations.',
                cwe='CWE-362',
                cvss=7.5,
                affected_url=target_url,
                evidence=f'Attacker: {a_success}/5 succeeded | Victim: {v_success}/5 succeeded\n'
                        f'Cross-account race condition confirmed.',
            )
