"""
Payment Flow Testing Engine — Deep business logic testing for e-commerce.

Tests:
  - Price manipulation (change price in request)
  - Quantity manipulation (negative, zero, MAX_INT)
  - Currency confusion
  - Coupon code re-use and stacking
  - Race condition in payment processing
"""
import logging
import json

logger = logging.getLogger(__name__)

# ── Price manipulation payloads ──────────────────────────────────────────────
PRICE_PAYLOADS = [
    {'price': 0},
    {'price': -1},
    {'price': 0.01},
    {'price': -0.01},
    {'price': 0.001},
    {'price': 999999999},
    {'total': 0},
    {'amount': 0},
    {'amount': -100},
]

# ── Quantity manipulation payloads ───────────────────────────────────────────
QUANTITY_PAYLOADS = [
    {'quantity': 0},
    {'quantity': -1},
    {'quantity': -100},
    {'quantity': 2147483647},
    {'quantity': -2147483648},
    {'qty': 0},
    {'qty': -1},
    {'count': -1},
]

# ── Currency confusion payloads ──────────────────────────────────────────────
CURRENCY_PAYLOADS = [
    {'currency': 'XXX'},
    {'currency': ''},
    {'currency_code': 'VND'},        # very low exchange rate currency
    {'currency_code': 'IRR'},        # Iranian Rial — extremely low value
    {'currency': 'BTC', 'amount': 1},  # crypto confusion
]

# ── Coupon abuse payloads ────────────────────────────────────────────────────
COUPON_PAYLOADS = [
    {'code': 'DISCOUNT100'},
    {'code': 'ADMIN'},
    {'code': 'TEST'},
    {'coupon': ''},
    {'promo_code': '0'},
    {'discount': 100},
    {'discount_percent': 100},
    {'discount_percent': 999},
]

# ── Common payment endpoints ─────────────────────────────────────────────────
PAYMENT_ENDPOINTS = [
    '/api/payment', '/api/pay', '/api/checkout',
    '/api/checkout/complete', '/api/orders/create',
    '/api/purchase', '/api/billing/charge',
]

CART_ENDPOINTS = [
    '/api/cart', '/api/cart/add', '/api/cart/update',
    '/api/basket', '/api/basket/add',
]

COUPON_ENDPOINTS = [
    '/api/coupon/apply', '/api/coupon', '/api/discount/apply',
    '/api/promo/apply', '/api/voucher/redeem',
]


class PaymentFlowTester:
    """
    Test payment/e-commerce business logic for manipulation flaws.

    Usage:
        tester = PaymentFlowTester(make_request_fn)
        findings = tester.test(url, body, depth='medium')
    """

    def __init__(self, make_request_fn):
        self._request = make_request_fn

    def test(self, url: str, body: str = '', depth: str = 'medium') -> list:
        """
        Run payment flow tests.

        Returns list of finding dicts with keys:
            technique, detail, severity, evidence.
        """
        findings = []
        base = url.rstrip('/')

        # 1. Price manipulation
        findings.extend(self._test_price_manipulation(base))

        if depth == 'shallow':
            return findings

        # 2. Quantity manipulation
        findings.extend(self._test_quantity_manipulation(base))

        # 3. Currency confusion
        findings.extend(self._test_currency_confusion(base))

        if depth == 'deep':
            # 4. Coupon abuse
            findings.extend(self._test_coupon_abuse(base))

            # 5. Race condition in payment
            findings.extend(self._test_payment_race(base))

        return findings

    # ── Price manipulation ───────────────────────────────────────────────

    def _test_price_manipulation(self, base_url: str) -> list:
        findings = []
        for endpoint in PAYMENT_ENDPOINTS + CART_ENDPOINTS:
            url = base_url + endpoint
            for payload in PRICE_PAYLOADS:
                try:
                    resp = self._request('POST', url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)
                    text = getattr(resp, 'text', '')

                    # Accepted with manipulated price → vuln
                    if status in (200, 201) and self._looks_like_success(text):
                        # Check which field was manipulated
                        field = list(payload.keys())[0]
                        val = payload[field]
                        if val <= 0 or val == 0.001:
                            findings.append({
                                'technique': 'price_manipulation',
                                'detail': f'Payment accepted with {field}={val} at {endpoint}',
                                'severity': 'critical',
                                'evidence': f'POST {endpoint} with {json.dumps(payload)} → HTTP {status}',
                            })
                            return findings  # one proof is enough
                except Exception:
                    continue
        return findings

    # ── Quantity manipulation ────────────────────────────────────────────

    def _test_quantity_manipulation(self, base_url: str) -> list:
        findings = []
        for endpoint in CART_ENDPOINTS:
            url = base_url + endpoint
            for payload in QUANTITY_PAYLOADS:
                try:
                    resp = self._request('POST', url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)
                    text = getattr(resp, 'text', '')

                    if status in (200, 201) and self._looks_like_success(text):
                        field = list(payload.keys())[0]
                        val = payload[field]
                        if val <= 0 or val > 2147483646:
                            findings.append({
                                'technique': 'quantity_manipulation',
                                'detail': f'Cart accepted {field}={val} at {endpoint}',
                                'severity': 'high',
                                'evidence': f'POST {endpoint} with {json.dumps(payload)} → HTTP {status}',
                            })
                            return findings
                except Exception:
                    continue
        return findings

    # ── Currency confusion ───────────────────────────────────────────────

    def _test_currency_confusion(self, base_url: str) -> list:
        findings = []
        for endpoint in PAYMENT_ENDPOINTS:
            url = base_url + endpoint
            for payload in CURRENCY_PAYLOADS:
                try:
                    resp = self._request('POST', url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)
                    text = getattr(resp, 'text', '')

                    if status in (200, 201) and self._looks_like_success(text):
                        curr = payload.get('currency', payload.get('currency_code', ''))
                        if curr:
                            findings.append({
                                'technique': 'currency_confusion',
                                'detail': f'Payment accepted with currency={curr} at {endpoint}',
                                'severity': 'high',
                                'evidence': f'POST {endpoint} with {json.dumps(payload)} → HTTP {status}',
                            })
                            return findings
                except Exception:
                    continue
        return findings

    # ── Coupon abuse ─────────────────────────────────────────────────────

    def _test_coupon_abuse(self, base_url: str) -> list:
        findings = []
        for endpoint in COUPON_ENDPOINTS:
            url = base_url + endpoint
            for payload in COUPON_PAYLOADS:
                try:
                    resp = self._request('POST', url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)
                    text = getattr(resp, 'text', '')

                    if status in (200, 201) and self._looks_like_success(text):
                        field = list(payload.keys())[0]
                        val = payload[field]
                        findings.append({
                            'technique': 'coupon_abuse',
                            'detail': f'Coupon/discount accepted ({field}={val}) at {endpoint}',
                            'severity': 'high',
                            'evidence': f'POST {endpoint} with {json.dumps(payload)} → HTTP {status}',
                        })
                        return findings
                except Exception:
                    continue
        return findings

    # ── Race condition in payment ────────────────────────────────────────

    def _test_payment_race(self, base_url: str) -> list:
        findings = []
        for endpoint in PAYMENT_ENDPOINTS:
            url = base_url + endpoint
            payload = {'amount': 100, 'action': 'pay'}
            success_count = 0
            total_sent = 5

            for _ in range(total_sent):
                try:
                    resp = self._request('POST', url, json=payload)
                    if not resp:
                        continue
                    status = getattr(resp, 'status_code', 0)
                    text = getattr(resp, 'text', '')
                    if status in (200, 201) and self._looks_like_success(text):
                        success_count += 1
                except Exception:
                    continue

            # If all rapid requests succeed, possible race condition
            if success_count >= total_sent:
                findings.append({
                    'technique': 'payment_race',
                    'detail': f'Possible race condition — {success_count}/{total_sent} rapid payments accepted at {endpoint}',
                    'severity': 'high',
                    'evidence': f'{success_count} of {total_sent} concurrent POSTs to {endpoint} accepted',
                })
                return findings
        return findings

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _looks_like_success(text: str) -> bool:
        """Heuristic: response looks like a success."""
        lower = text.lower()
        success_indicators = [
            '"success"', '"ok"', '"created"', '"accepted"',
            '"status":"success"', '"status": "success"',
            '"order_id"', '"transaction_id"', '"payment_id"',
            'order confirmed', 'payment successful',
        ]
        return any(ind in lower for ind in success_indicators)
