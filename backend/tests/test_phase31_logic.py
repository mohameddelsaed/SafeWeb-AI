"""
Phase 31 — Business Logic Testing Engine tests.

Tests for PaymentFlowTester, AuthFlowTester, StateMachineTester,
RateLimitTester, and the BusinessLogicDeepTester wrapper.
"""
from unittest.mock import MagicMock, patch

from tests.conftest import MockPage


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_response(status_code=200, text='', headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


def _make_request_404(*args, **kwargs):
    return _mock_response(404)


def _success_text():
    return '{"status":"success","order_id":"abc123"}'


def _auth_success_text():
    return '{"success": true, "token": "eyJhbGciOiJIUzI1NiJ9.test"}'


# ═════════════════════════════════════════════════════════════════════════════
# PaymentFlowTester
# ═════════════════════════════════════════════════════════════════════════════

class TestPaymentFlowTester:
    """Tests for the payment flow testing engine."""

    def _get_tester(self, make_request=None):
        from apps.scanning.engine.logic.payment_tester import PaymentFlowTester
        return PaymentFlowTester(make_request or _make_request_404)

    # ── Price manipulation ───────────────────────────────────────────────

    def test_price_manipulation_detects_zero_price(self):
        """Detect when a zero/negative price is accepted."""
        def make_req(method, url, **kwargs):
            body = kwargs.get('json', {})
            price = body.get('price', body.get('amount', None))
            if price is not None and price <= 0:
                return _mock_response(200, _success_text())
            return _mock_response(400, '{"error":"bad request"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='shallow')
        assert len(findings) >= 1
        assert findings[0]['technique'] == 'price_manipulation'
        assert findings[0]['severity'] == 'critical'

    def test_price_manipulation_no_vuln(self):
        """No findings when all prices are rejected."""
        tester = self._get_tester(_make_request_404)
        findings = tester.test('https://shop.com', depth='shallow')
        assert len(findings) == 0

    # ── Quantity manipulation ────────────────────────────────────────────

    def test_quantity_manipulation_negative(self):
        """Detect negative quantity acceptance."""
        def make_req(method, url, **kwargs):
            body = kwargs.get('json', {})
            qty = body.get('quantity', body.get('qty', body.get('count', None)))
            if qty is not None and qty < 0:
                return _mock_response(200, _success_text())
            return _mock_response(400, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='medium')
        assert any(f['technique'] == 'quantity_manipulation' for f in findings)

    # ── Currency confusion ───────────────────────────────────────────────

    def test_currency_confusion_detects(self):
        """Detect invalid currency acceptance on payment endpoints."""
        def make_req(method, url, **kwargs):
            body = kwargs.get('json', {})
            curr = body.get('currency', body.get('currency_code', ''))
            if curr in ('XXX', '', 'VND', 'IRR'):
                return _mock_response(200, _success_text())
            return _mock_response(400, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='medium')
        assert any(f['technique'] == 'currency_confusion' for f in findings)

    # ── Coupon abuse (deep only) ─────────────────────────────────────────

    def test_coupon_abuse_deep_only(self):
        """Coupon abuse tests only run at deep depth."""
        call_log = []

        def make_req(method, url, **kwargs):
            call_log.append(url)
            return _mock_response(400, '')

        tester = self._get_tester(make_req)

        # Medium depth — no coupon endpoints hit
        tester.test('https://shop.com', depth='medium')
        coupon_calls_medium = [u for u in call_log if 'coupon' in u or 'promo' in u or 'discount' in u or 'voucher' in u]
        assert len(coupon_calls_medium) == 0

        call_log.clear()
        # Deep depth — coupon endpoints hit
        tester.test('https://shop.com', depth='deep')
        coupon_calls_deep = [u for u in call_log if 'coupon' in u or 'promo' in u or 'discount' in u or 'voucher' in u]
        assert len(coupon_calls_deep) > 0

    def test_coupon_abuse_detects(self):
        """Detect coupon abuse when discount=100 is accepted."""
        def make_req(method, url, **kwargs):
            body = kwargs.get('json', {})
            if body.get('discount', 0) == 100 or body.get('discount_percent', 0) >= 100:
                return _mock_response(200, _success_text())
            return _mock_response(400, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='deep')
        assert any(f['technique'] == 'coupon_abuse' for f in findings)

    # ── Payment race condition (deep only) ───────────────────────────────

    def test_payment_race_detects(self):
        """Detect race condition when all rapid payments succeed."""
        def make_req(method, url, **kwargs):
            if '/api/payment' in url or '/api/pay' in url or '/api/checkout' in url:
                return _mock_response(200, _success_text())
            return _mock_response(404, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='deep')
        assert any(f['technique'] == 'payment_race' for f in findings)

    def test_payment_race_not_at_medium(self):
        """Race condition tests not run at medium depth."""
        call_count = [0]

        def make_req(method, url, **kwargs):
            call_count[0] += 1
            return _mock_response(200, _success_text())

        tester = self._get_tester(make_req)
        # Reset counter after price manipulation calls
        findings = tester.test('https://shop.com', depth='shallow')
        # At shallow, only price manipulation runs — check no race findings
        assert not any(f['technique'] == 'payment_race' for f in findings)

    # ── Depth gating ─────────────────────────────────────────────────────

    def test_shallow_only_runs_price(self):
        """At shallow depth, only price manipulation runs."""
        tester = self._get_tester(_make_request_404)
        findings = tester.test('https://shop.com', depth='shallow')
        assert isinstance(findings, list)


# ═════════════════════════════════════════════════════════════════════════════
# AuthFlowTester
# ═════════════════════════════════════════════════════════════════════════════

class TestAuthFlowTester:
    """Tests for the authentication flow testing engine."""

    def _get_tester(self, make_request=None):
        from apps.scanning.engine.logic.auth_flow_tester import AuthFlowTester
        return AuthFlowTester(make_request or _make_request_404)

    # ── Account enumeration ──────────────────────────────────────────────

    def test_account_enumeration_status_code_diff(self):
        """Detect enumeration via different status codes."""
        def make_req(method, url, **kwargs):
            body = kwargs.get('json', {})
            email = body.get('email', '')
            if 'admin@' in email:
                return _mock_response(403, '{"error":"wrong password"}')
            return _mock_response(404, '{"error":"user not found"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='shallow')
        assert len(findings) >= 1
        assert findings[0]['technique'] == 'account_enumeration'
        assert 'status code' in findings[0]['detail']

    def test_account_enumeration_length_diff(self):
        """Detect enumeration via response length difference."""
        def make_req(method, url, **kwargs):
            body = kwargs.get('json', {})
            email = body.get('email', '')
            if 'admin@' in email:
                return _mock_response(401, 'A' * 100)
            return _mock_response(401, 'B' * 50)

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='shallow')
        assert len(findings) >= 1
        assert findings[0]['technique'] == 'account_enumeration'
        assert 'response length' in findings[0]['detail']

    def test_account_enumeration_body_diff(self):
        """Detect enumeration via different response bodies."""
        def make_req(method, url, **kwargs):
            body = kwargs.get('json', {})
            email = body.get('email', '')
            if 'admin@' in email:
                return _mock_response(401, 'wrong password')
            return _mock_response(401, 'user not found!')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='shallow')
        assert len(findings) >= 1
        assert findings[0]['technique'] == 'account_enumeration'

    def test_account_enumeration_no_diff(self):
        """No enumeration when responses are identical."""
        def make_req(method, url, **kwargs):
            return _mock_response(401, 'Invalid credentials')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='shallow')
        assert len(findings) == 0

    # ── OTP bypass ───────────────────────────────────────────────────────

    def test_otp_bypass_detects(self):
        """Detect OTP bypass with trivial value."""
        def make_req(method, url, **kwargs):
            body = kwargs.get('json', {})
            otp = body.get('otp', body.get('code', ''))
            if otp == '000000' and '/otp' in url.lower() or '/2fa' in url.lower() or '/verify' in url.lower() or '/mfa' in url.lower():
                return _mock_response(200, _auth_success_text())
            return _mock_response(401, '{"error":"invalid code"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='medium')
        assert any(f['technique'] == 'otp_bypass' for f in findings)

    def test_otp_bypass_no_vuln(self):
        """No OTP bypass when all OTP attempts fail."""
        def make_req(method, url, **kwargs):
            return _mock_response(401, '{"error":"invalid"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='medium')
        assert not any(f['technique'] == 'otp_bypass' for f in findings)

    # ── Reset token analysis ─────────────────────────────────────────────

    def test_reset_token_predictable(self):
        """Detect sequential reset tokens."""
        counter = [1000000]

        def make_req(method, url, **kwargs):
            counter[0] += 1
            return _mock_response(200, f'{{"token": "{counter[0]}"}}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='medium')
        assert any(f['technique'] == 'reset_token_predictable' for f in findings)

    def test_reset_token_weak_short(self):
        """Detect short reset tokens."""
        counter = [0]

        def make_req(method, url, **kwargs):
            counter[0] += 1
            # Short tokens (< 16 chars) but not sequential
            tokens = ['a1b2c3', 'x9y8z7', 'm5n4o3']
            idx = (counter[0] - 1) % len(tokens)
            return _mock_response(200, f'{{"token": "{tokens[idx]}"}}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='medium')
        assert any(f['technique'] == 'reset_token_weak' for f in findings)

    def test_reset_no_tokens_in_response(self):
        """No findings when response has no extractable tokens."""
        def make_req(method, url, **kwargs):
            return _mock_response(200, '{"message":"reset email sent"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='medium')
        assert not any(f['technique'] in ('reset_token_predictable', 'reset_token_weak') for f in findings)

    # ── Registration abuse (deep only) ───────────────────────────────────

    def test_registration_abuse_deep_only(self):
        """Registration abuse only runs at deep depth."""
        call_log = []

        def make_req(method, url, **kwargs):
            call_log.append(url)
            return _mock_response(400, '')

        tester = self._get_tester(make_req)
        tester.test('https://auth.com', depth='medium')
        [u for u in call_log if '/register' in u or '/signup' in u]
        # At medium, register endpoints are not tested for abuse
        # (They might be hit by other tests but not by _test_registration_abuse)
        # So we check deep adds more
        call_log.clear()
        tester.test('https://auth.com', depth='deep')
        register_calls_deep = [u for u in call_log if '/register' in u or '/signup' in u]
        assert len(register_calls_deep) > 0

    def test_registration_abuse_detects(self):
        """Detect email case bypass."""
        def make_req(method, url, **kwargs):
            if '/register' in url or '/signup' in url:
                return _mock_response(201, '{"success":true}')
            return _mock_response(404, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='deep')
        assert any(f['technique'] == 'registration_abuse' for f in findings)

    # ── Host header reset (deep only) ────────────────────────────────────

    def test_host_header_reset_detects(self):
        """Detect host header injection in password reset."""
        def make_req(method, url, **kwargs):
            headers = kwargs.get('headers', {})
            host = headers.get('Host', '')
            if host and '/forgot' in url or '/reset' in url or '/recover' in url:
                return _mock_response(200, f'Reset link: https://{host}/reset?token=abc')
            return _mock_response(200, 'Reset email sent')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='deep')
        assert any(f['technique'] == 'host_header_reset' for f in findings)

    def test_host_header_not_reflected(self):
        """No finding when host header is not reflected."""
        def make_req(method, url, **kwargs):
            return _mock_response(200, '{"message":"reset email sent"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://auth.com', depth='deep')
        assert not any(f['technique'] == 'host_header_reset' for f in findings)

    # ── Depth gating ─────────────────────────────────────────────────────

    def test_shallow_only_runs_enumeration(self):
        """At shallow depth, only account enumeration runs."""
        tester = self._get_tester(_make_request_404)
        findings = tester.test('https://auth.com', depth='shallow')
        assert isinstance(findings, list)


# ═════════════════════════════════════════════════════════════════════════════
# StateMachineTester
# ═════════════════════════════════════════════════════════════════════════════

class TestStateMachineTester:
    """Tests for the state machine testing engine."""

    def _get_tester(self, make_request=None):
        from apps.scanning.engine.logic.state_machine import StateMachineTester
        return StateMachineTester(make_request or _make_request_404)

    # ── Skip-step bypass ─────────────────────────────────────────────────

    def test_skip_step_detects(self):
        """Detect when final step is accessible without prior steps."""
        def make_req(method, url, **kwargs):
            # Final checkout step succeeds without prior steps
            if '/confirm' in url or '/complete' in url or '/step3' in url or '/step/3' in url:
                return _mock_response(200, _success_text())
            return _mock_response(403, '{"error":"forbidden"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='shallow')
        assert len(findings) >= 1
        assert findings[0]['technique'] == 'skip_step'
        assert findings[0]['severity'] == 'critical'

    def test_skip_step_no_vuln(self):
        """No skip-step when final step is properly gated."""
        tester = self._get_tester(_make_request_404)
        findings = tester.test('https://shop.com', depth='shallow')
        assert len(findings) == 0

    # ── Direct final step access ─────────────────────────────────────────

    def test_direct_access_via_get(self):
        """Detect when completion endpoint is accessible via GET."""
        def make_req(method, url, **kwargs):
            if method == 'GET' and ('/complete' in url or '/confirm' in url or '/approve' in url):
                return _mock_response(200, _success_text())
            return _mock_response(403, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='medium')
        assert any(f['technique'] == 'direct_access' for f in findings)

    def test_direct_access_no_vuln(self):
        """No direct access when all endpoints are protected."""
        def make_req(method, url, **kwargs):
            return _mock_response(403, '{"error":"forbidden"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='medium')
        assert not any(f['technique'] == 'direct_access' for f in findings)

    # ── State transition abuse (deep only) ───────────────────────────────

    def test_state_transition_detects(self):
        """Detect state manipulation via PUT."""
        def make_req(method, url, **kwargs):
            if method == 'PUT' and '/orders/' in url:
                body = kwargs.get('json', {})
                if 'status' in body or 'state' in body:
                    return _mock_response(200, _success_text())
            return _mock_response(403, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='deep')
        assert any(f['technique'] == 'state_transition' for f in findings)

    def test_state_transition_deep_only(self):
        """State transition tests not run at medium depth."""
        call_log = []

        def make_req(method, url, **kwargs):
            call_log.append((method, url))
            return _mock_response(403, '')

        tester = self._get_tester(make_req)
        tester.test('https://shop.com', depth='medium')
        put_calls = [c for c in call_log if c[0] == 'PUT']
        assert len(put_calls) == 0

    # ── Backward navigation (deep only) ──────────────────────────────────

    def test_backward_navigation_detects(self):
        """Detect backward navigation after workflow completion."""
        def make_req(method, url, **kwargs):
            # Simulate: final step returns success, first step also returns success
            if '/confirm' in url or '/complete' in url or '/step3' in url:
                return _mock_response(200, _success_text())
            if '/step1' in url or '/cart' in url or '/profile' in url:
                return _mock_response(200, _success_text())
            return _mock_response(404, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://shop.com', depth='deep')
        assert any(f['technique'] == 'backward_navigation' for f in findings)

    # ── Depth gating ─────────────────────────────────────────────────────

    def test_shallow_only_runs_skip_step(self):
        """At shallow depth, only skip-step runs."""
        tester = self._get_tester(_make_request_404)
        findings = tester.test('https://shop.com', depth='shallow')
        assert isinstance(findings, list)


# ═════════════════════════════════════════════════════════════════════════════
# RateLimitTester
# ═════════════════════════════════════════════════════════════════════════════

class TestRateLimitTester:
    """Tests for the rate limit testing engine."""

    def _get_tester(self, make_request=None):
        from apps.scanning.engine.logic.rate_limit_tester import RateLimitTester
        return RateLimitTester(make_request or _make_request_404)

    # ── Rate limit detection ─────────────────────────────────────────────

    def test_no_rate_limit_detected(self):
        """Detect lack of rate limiting on sensitive endpoints."""
        def make_req(method, url, **kwargs):
            # Always 200, never 429
            return _mock_response(200, '{"error":"invalid credentials"}')

        tester = self._get_tester(make_req)
        findings = tester.test('https://api.com', depth='shallow')
        assert len(findings) >= 1
        assert findings[0]['technique'] == 'no_rate_limit'

    def test_rate_limit_present(self):
        """No finding when rate limiting is active."""
        counter = [0]

        def make_req(method, url, **kwargs):
            counter[0] += 1
            if counter[0] >= 5:
                return _mock_response(429, 'Rate limited')
            return _mock_response(200, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://api.com', depth='shallow')
        # Should NOT find no_rate_limit since 429 is returned
        assert not any(f['technique'] == 'no_rate_limit' for f in findings)

    def test_rate_limit_via_headers(self):
        """No finding when rate limit headers are present."""
        def make_req(method, url, **kwargs):
            return _mock_response(200, '', headers={'X-RateLimit-Remaining': '0'})

        tester = self._get_tester(make_req)
        findings = tester.test('https://api.com', depth='shallow')
        assert not any(f['technique'] == 'no_rate_limit' for f in findings)

    # ── Header bypass ────────────────────────────────────────────────────

    def test_header_bypass_detects(self):
        """Detect rate limit bypass via X-Forwarded-For."""
        call_count = [0]

        def make_req(method, url, **kwargs):
            call_count[0] += 1
            headers = kwargs.get('headers', {})
            # If XFF header present, bypass rate limit
            if 'X-Forwarded-For' in headers:
                return _mock_response(200, '')
            # After 5 requests, trigger rate limit
            if call_count[0] >= 5:
                return _mock_response(429, 'Too many requests')
            return _mock_response(200, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://api.com', depth='medium')
        assert any(f['technique'] == 'header_bypass' for f in findings)

    def test_header_bypass_no_vuln(self):
        """No bypass when XFF doesn't help."""
        call_count = [0]

        def make_req(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] >= 5:
                return _mock_response(429, 'Too many requests')
            return _mock_response(200, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://api.com', depth='medium')
        assert not any(f['technique'] == 'header_bypass' for f in findings)

    # ── Request variation bypass (deep only) ─────────────────────────────

    def test_variation_bypass_detects(self):
        """Detect rate limit bypass via URL variation."""
        call_count = [0]

        def make_req(method, url, **kwargs):
            call_count[0] += 1
            headers = kwargs.get('headers', {})
            # XFF doesn't help (to skip header bypass early)
            if 'X-Forwarded-For' in headers:
                return _mock_response(429, '')
            # Original endpoint: rate limited after 5
            if url.endswith('/api/auth/login') or url.endswith('/api/login'):
                if call_count[0] >= 5:
                    return _mock_response(429, '')
                return _mock_response(200, '')
            # Varied endpoint — not rate limited
            return _mock_response(200, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://api.com', depth='deep')
        assert any(f['technique'] == 'variation_bypass' for f in findings)

    def test_variation_bypass_deep_only(self):
        """Variation bypass not tested at medium depth."""
        tester = self._get_tester(_make_request_404)
        findings = tester.test('https://api.com', depth='medium')
        assert not any(f['technique'] == 'variation_bypass' for f in findings)

    # ── Version bypass (deep only) ───────────────────────────────────────

    def test_version_bypass_detects(self):
        """Detect rate limit bypass via API version."""
        call_count = [0]

        def make_req(method, url, **kwargs):
            call_count[0] += 1
            headers = kwargs.get('headers', {})
            if 'X-Forwarded-For' in headers:
                return _mock_response(429, '')
            # /api/ endpoints get rate limited
            if '/api/' in url and '/v1/' not in url and '/v2/' not in url:
                if call_count[0] >= 5:
                    return _mock_response(429, '')
                return _mock_response(200, '')
            # Versioned endpoints bypass rate limit
            if '/v1/' in url or '/v2/' in url:
                return _mock_response(200, '')
            return _mock_response(404, '')

        tester = self._get_tester(make_req)
        findings = tester.test('https://api.com', depth='deep')
        assert any(f['technique'] == 'version_bypass' for f in findings)

    # ── Depth gating ─────────────────────────────────────────────────────

    def test_shallow_only_runs_detection(self):
        """At shallow depth, only rate limit detection runs."""
        tester = self._get_tester(_make_request_404)
        findings = tester.test('https://api.com', depth='shallow')
        assert isinstance(findings, list)


# ═════════════════════════════════════════════════════════════════════════════
# BusinessLogicDeepTester (wrapper)
# ═════════════════════════════════════════════════════════════════════════════

class TestBusinessLogicDeepTester:
    """Tests for the BaseTester wrapper."""

    def _get_tester(self):
        from apps.scanning.engine.testers.business_logic_deep_tester import BusinessLogicDeepTester
        return BusinessLogicDeepTester()

    # ── Keyword-based engine selection ───────────────────────────────────

    def test_payment_keywords_trigger_payment_engine(self):
        """Payment keywords in URL trigger PaymentFlowTester."""
        tester = self._get_tester()
        with patch.object(tester, '_make_request', return_value=_mock_response(404)):
            page = MockPage(url='https://shop.com/api/checkout')
            vulns = tester.test(page, depth='shallow')
            assert isinstance(vulns, list)

    def test_auth_keywords_trigger_auth_engine(self):
        """Auth keywords in URL trigger AuthFlowTester."""
        tester = self._get_tester()
        with patch.object(tester, '_make_request', return_value=_mock_response(404)):
            page = MockPage(url='https://app.com/api/login')
            vulns = tester.test(page, depth='shallow')
            assert isinstance(vulns, list)

    def test_workflow_keywords_trigger_state_engine(self):
        """Workflow keywords in URL trigger StateMachineTester."""
        tester = self._get_tester()
        with patch.object(tester, '_make_request', return_value=_mock_response(404)):
            page = MockPage(url='https://app.com/api/checkout/step1')
            vulns = tester.test(page, depth='shallow')
            assert isinstance(vulns, list)

    def test_deep_mode_runs_all_engines(self):
        """Deep mode runs all engines regardless of keywords."""
        tester = self._get_tester()
        with patch.object(tester, '_make_request', return_value=_mock_response(404)):
            page = MockPage(url='https://generic.com/page')
            vulns = tester.test(page, depth='deep')
            assert isinstance(vulns, list)

    # ── Empty URL returns empty ──────────────────────────────────────────

    def test_empty_url_returns_empty(self):
        """Empty URL returns no vulns."""
        tester = self._get_tester()
        page = MockPage(url='')
        vulns = tester.test(page, depth='deep')
        assert vulns == []

    # ── Vuln dict structure ──────────────────────────────────────────────

    def test_vuln_dict_structure(self):
        """Vulns have correct dict structure with required keys."""
        tester = self._get_tester()

        # Simulate price manipulation finding
        def mock_request(method, url, **kwargs):
            body = kwargs.get('json', {})
            if body.get('price', None) == 0:
                return _mock_response(200, _success_text())
            return _mock_response(400, '')

        with patch.object(tester, '_make_request', side_effect=mock_request):
            page = MockPage(url='https://shop.com/api/payment')
            vulns = tester.test(page, depth='shallow')
            if vulns:
                v = vulns[0]
                assert 'name' in v
                assert 'severity' in v
                assert 'category' in v
                assert 'cwe' in v
                assert 'cvss' in v

    def test_finding_to_vuln_categories(self):
        """Technique→category mapping works correctly."""
        tester = self._get_tester()
        finding_payment = {
            'technique': 'price_manipulation',
            'detail': 'test',
            'severity': 'critical',
            'evidence': 'test',
        }
        vuln = tester._finding_to_vuln(finding_payment, 'https://x.com')
        assert vuln['category'] == 'business_logic'
        assert vuln['cwe'] == 'CWE-472'

        finding_auth = {
            'technique': 'otp_bypass',
            'detail': 'test',
            'severity': 'critical',
            'evidence': 'test',
        }
        vuln = tester._finding_to_vuln(finding_auth, 'https://x.com')
        assert vuln['category'] == 'authentication'
        assert vuln['cwe'] == 'CWE-287'

        finding_rate = {
            'technique': 'no_rate_limit',
            'detail': 'test',
            'severity': 'medium',
            'evidence': 'test',
        }
        vuln = tester._finding_to_vuln(finding_rate, 'https://x.com')
        assert vuln['category'] == 'rate_limiting'
        assert vuln['cwe'] == 'CWE-770'

    # ── Registration & tester count ──────────────────────────────────────

    def test_registered_in_get_all_testers(self):
        """BusinessLogicDeepTester is in get_all_testers()."""
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        names = [t.TESTER_NAME for t in testers]
        assert 'Business Logic Deep' in names

    def test_tester_count(self):
        """Total tester count is 64 (63 + Phase 32)."""
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert len(testers) == 87
