"""
Business Logic Tester — Detects business logic flaws that are not
caught by traditional injection/misconfiguration scanners.

Covers:
  - Price / discount manipulation
  - Workflow step bypass (skipping required steps)
  - Quantity / limit circumvention (negative quantities, max bypass)
  - Parameter tampering (role escalation, privilege modification)
  - Race condition / TOCTOU in business operations
  - Coupon / voucher abuse
  - Numeric overflow in financial fields
"""
import json
import logging
import threading

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Manipulation payloads ────────────────────────────────────────────────────
PRICE_MANIPULATIONS = [
    0, -1, -100, 0.001, 0.01, 999999999,
    -0.01, -999, 0.00,
]

QUANTITY_MANIPULATIONS = [
    0, -1, -100, 999999, 2147483647, -2147483648,
]

ROLE_ESCALATION_VALUES = [
    'admin', 'administrator', 'root', 'superuser', 'staff',
    'moderator', 'manager', 'super_admin', 'system',
]

# ── Common e-commerce / business endpoints ───────────────────────────────────
CART_ENDPOINTS = [
    '/api/cart', '/api/cart/add', '/cart/add', '/api/basket',
    '/api/orders', '/api/checkout', '/checkout',
]

PAYMENT_ENDPOINTS = [
    '/api/payment', '/api/pay', '/api/checkout/complete',
    '/api/orders/create', '/api/purchase',
]

COUPON_ENDPOINTS = [
    '/api/coupon', '/api/coupon/apply', '/api/discount',
    '/api/promo', '/api/voucher', '/api/coupon/redeem',
]

WORKFLOW_ENDPOINTS = [
    '/api/checkout/step1', '/api/checkout/step2', '/api/checkout/step3',
    '/api/checkout/confirm', '/api/checkout/complete',
    '/api/onboarding/step1', '/api/onboarding/step2', '/api/onboarding/complete',
    '/api/verify', '/api/verify/confirm',
]


class BusinessLogicTester(BaseTester):
    """Detects business logic vulnerabilities."""

    TESTER_NAME = 'Business Logic'
    REQUEST_TIMEOUT = 10

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        """Test for business logic flaws."""
        vulns = []
        target = getattr(page, 'url', '')

        # 1. Price / quantity manipulation
        vulns.extend(self._test_price_manipulation(target, depth))

        # 2. Workflow step bypass
        vulns.extend(self._test_workflow_bypass(target, depth))

        # 3. Parameter tampering / role escalation
        vulns.extend(self._test_parameter_tampering(target, depth))

        # 4. Coupon / discount abuse
        if depth in ('medium', 'deep'):
            vulns.extend(self._test_coupon_abuse(target))

        # 5. Race condition in business operations
        if depth == 'deep':
            vulns.extend(self._test_race_conditions(target))

        # 6. Numeric overflow
        if depth in ('medium', 'deep'):
            vulns.extend(self._test_numeric_overflow(target))

        return vulns

    def _test_price_manipulation(self, target: str, depth: str) -> list:
        """Test for price and quantity manipulation."""
        vulns = []
        base = target.rstrip('/')

        for endpoint in CART_ENDPOINTS:
            url = base + endpoint
            headers = {'Content-Type': 'application/json'}

            # Test negative price
            payloads = [
                {'product_id': 1, 'quantity': 1, 'price': -100},
                {'product_id': 1, 'quantity': -1, 'price': 10},
                {'product_id': 1, 'quantity': 1, 'price': 0},
                {'product_id': 1, 'quantity': 1, 'price': 0.01},
            ]

            if depth == 'shallow':
                payloads = payloads[:2]

            for payload in payloads:
                resp = self._make_request('POST', url, json=payload, headers=headers)
                if not resp:
                    continue

                status = resp.status_code
                body = resp.text or ''

                if status in (200, 201):
                    # Check if negative/zero price was accepted
                    price_val = payload.get('price', payload.get('quantity'))
                    if price_val is not None and (price_val <= 0 or price_val == 0.01):
                        # Look for acceptance indicators
                        try:
                            data = json.loads(body)
                            total = data.get('total', data.get('subtotal', data.get('amount')))
                            if total is not None and (float(total) <= 0 or float(total) < 1):
                                vuln_name = 'Negative Price' if price_val < 0 else 'Zero/Minimal Price'
                                vulns.append(self._build_vuln(
                                    name=f'Price Manipulation — {vuln_name} Accepted',
                                    severity='critical',
                                    category='Business Logic',
                                    description=(
                                        f'The endpoint {url} accepted a {vuln_name.lower()} '
                                        f'value ({price_val}), resulting in a total of {total}. '
                                        f'This enables financial fraud.'
                                    ),
                                    impact=(
                                        'Financial loss — attackers can purchase items for '
                                        'free or negative amounts, potentially crediting '
                                        'their account.'
                                    ),
                                    remediation=(
                                        '1. Validate all prices server-side (must be > 0). '
                                        '2. Never trust client-supplied price values. '
                                        '3. Calculate prices from product catalog on the server. '
                                        '4. Log and alert on anomalous price values.'
                                    ),
                                    cwe='CWE-20',
                                    cvss=9.1,
                                    affected_url=url,
                                    evidence=f'Payload: {json.dumps(payload)}\nResponse total: {total}',
                                ))
                                return vulns
                        except (json.JSONDecodeError, ValueError, TypeError):
                            pass

                    # Check for negative quantity acceptance
                    qty = payload.get('quantity', 0)
                    if qty < 0 and status in (200, 201):
                        vulns.append(self._build_vuln(
                            name='Quantity Manipulation — Negative Quantity Accepted',
                            severity='high',
                            category='Business Logic',
                            description=(
                                f'The endpoint {url} accepted a negative quantity ({qty}), '
                                f'potentially allowing credit or refund manipulation.'
                            ),
                            impact='Financial manipulation via negative quantity orders.',
                            remediation=(
                                '1. Validate quantities server-side (must be >= 1). '
                                '2. Use unsigned integers for quantity fields.'
                            ),
                            cwe='CWE-20',
                            cvss=8.0,
                            affected_url=url,
                            evidence=f'Negative quantity ({qty}) accepted with HTTP {status}.',
                        ))
                        return vulns

        return vulns

    def _test_workflow_bypass(self, target: str, depth: str) -> list:
        """Test for workflow step bypass (skipping validation/payment)."""
        vulns = []
        base = target.rstrip('/')

        # Try accessing final workflow steps directly without completing earlier steps
        final_steps = [
            ('/api/checkout/complete', 'Checkout completion'),
            ('/api/checkout/confirm', 'Checkout confirmation'),
            ('/api/checkout/step3', 'Checkout step 3'),
            ('/api/onboarding/complete', 'Onboarding completion'),
            ('/api/verify/confirm', 'Verification confirmation'),
            ('/api/orders/create', 'Order creation'),
        ]

        for path, step_name in final_steps:
            url = base + path

            # POST without completing prerequisites
            body = {'confirmed': True, 'step_completed': True}
            resp = self._make_request('POST', url, json=body)
            if not resp:
                continue

            status = resp.status_code
            resp_body = resp.text or ''

            if status in (200, 201):
                # Check if it looks like a successful action
                try:
                    data = json.loads(resp_body)
                    success_indicators = ['success', 'order_id', 'confirmation', 'completed', 'id']
                    if any(k in data for k in success_indicators):
                        vulns.append(self._build_vuln(
                            name=f'Workflow Step Bypass — {step_name}',
                            severity='high',
                            category='Business Logic',
                            description=(
                                f'The {step_name} endpoint ({url}) can be accessed directly '
                                f'without completing prerequisite steps. This enables '
                                f'bypassing validation, payment, or verification workflows.'
                            ),
                            impact=(
                                'Bypassing payment (free orders), skipping identity '
                                'verification, or completing actions without required '
                                'authorization steps.'
                            ),
                            remediation=(
                                '1. Enforce server-side workflow state tracking. '
                                '2. Verify all prerequisite steps before allowing progression. '
                                '3. Use session-bound workflow tokens to enforce order. '
                                '4. Never rely on client-side workflow enforcement.'
                            ),
                            cwe='CWE-841',
                            cvss=8.0,
                            affected_url=url,
                            evidence=f'Direct POST succeeded with: {resp_body[:300]}',
                        ))
                        return vulns
                except (json.JSONDecodeError, TypeError):
                    pass

        return vulns

    def _test_parameter_tampering(self, target: str, depth: str) -> list:
        """Test for role/privilege escalation via parameter tampering."""
        vulns = []
        base = target.rstrip('/')

        profile_endpoints = [
            '/api/user/profile', '/api/user/settings', '/api/users/me',
            '/api/account', '/api/profile',
        ]

        for endpoint in profile_endpoints:
            url = base + endpoint

            for role in ROLE_ESCALATION_VALUES[:5]:
                # Try to set role via various parameter names
                role_payloads = [
                    {'role': role},
                    {'is_admin': True},
                    {'isAdmin': True},
                    {'user_type': role},
                    {'permissions': ['admin', 'write', 'delete']},
                    {'level': 99},
                ]

                for payload in role_payloads:
                    resp = self._make_request('PUT', url, json=payload)
                    if not resp:
                        resp = self._make_request('PATCH', url, json=payload)
                    if not resp:
                        continue

                    status = resp.status_code
                    body = resp.text or ''

                    if status in (200, 201):
                        try:
                            data = json.loads(body)
                            # Check if role was actually changed
                            if data.get('role') == role or data.get('is_admin') is True or \
                               data.get('isAdmin') is True or data.get('user_type') == role:
                                vulns.append(self._build_vuln(
                                    name='Privilege Escalation via Parameter Tampering',
                                    severity='critical',
                                    category='Business Logic',
                                    description=(
                                        f'The endpoint {url} accepted a role/privilege change '
                                        f'to "{role}" via direct parameter modification. '
                                        f'The application does not enforce server-side '
                                        f'authorization for privilege changes.'
                                    ),
                                    impact=(
                                        'Complete privilege escalation — any user can become '
                                        'an admin by modifying their profile parameters.'
                                    ),
                                    remediation=(
                                        '1. Never accept role/permission changes from user input. '
                                        '2. Enforce role changes via admin-only endpoints. '
                                        '3. Use allowlists for modifiable profile fields. '
                                        '4. Implement mass assignment protection.'
                                    ),
                                    cwe='CWE-269',
                                    cvss=9.8,
                                    affected_url=url,
                                    evidence=f'Payload: {json.dumps(payload)}\nResponse: {body[:300]}',
                                ))
                                return vulns
                        except (json.JSONDecodeError, TypeError):
                            pass

        return vulns

    def _test_coupon_abuse(self, target: str) -> list:
        """Test for coupon/discount code abuse."""
        vulns = []
        base = target.rstrip('/')

        for endpoint in COUPON_ENDPOINTS:
            url = base + endpoint

            # Test 1: Apply same coupon multiple times
            test_coupon = {'code': 'TEST10', 'coupon_code': 'DISCOUNT'}
            first_resp = self._make_request('POST', url, json=test_coupon)
            if not first_resp or first_resp.status_code not in (200, 201):
                continue

            second_resp = self._make_request('POST', url, json=test_coupon)
            if second_resp and second_resp.status_code in (200, 201):
                try:
                    first_data = json.loads(first_resp.text or '{}')
                    second_data = json.loads(second_resp.text or '{}')

                    first_discount = first_data.get('discount', first_data.get('total', 0))
                    second_discount = second_data.get('discount', second_data.get('total', 0))

                    if first_discount and second_discount:
                        vulns.append(self._build_vuln(
                            name='Coupon Code Reuse — Multiple Application',
                            severity='medium',
                            category='Business Logic',
                            description=(
                                f'The coupon endpoint {url} allows the same coupon code '
                                f'to be applied multiple times, potentially stacking discounts.'
                            ),
                            impact='Financial loss through stacked discount exploitation.',
                            remediation=(
                                '1. Track applied coupons per session/order. '
                                '2. Reject duplicate coupon applications. '
                                '3. Validate coupon state server-side before applying.'
                            ),
                            cwe='CWE-840',
                            cvss=6.5,
                            affected_url=url,
                            evidence='Coupon accepted on both first and second application.',
                        ))
                        break
                except (json.JSONDecodeError, TypeError):
                    pass

        return vulns

    def _test_race_conditions(self, target: str) -> list:
        """Test for race conditions in business operations."""
        vulns = []
        base = target.rstrip('/')

        # Test race condition on a transfer/payment endpoint
        race_endpoints = [
            '/api/transfer', '/api/payment', '/api/coupon/redeem',
            '/api/withdraw', '/api/points/redeem',
        ]

        for endpoint in race_endpoints:
            url = base + endpoint
            payload = {'amount': 1, 'to': 'test'}
            results = []
            errors = []

            def send_request():
                try:
                    resp = self._make_request('POST', url, json=payload)
                    if resp:
                        results.append(resp.status_code)
                except Exception as e:
                    errors.append(str(e))

            # Send concurrent requests
            threads = []
            for _ in range(5):
                t = threading.Thread(target=send_request)
                threads.append(t)

            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

            # If all 5 succeeded, potential race condition
            success_count = sum(1 for s in results if s in (200, 201))
            if success_count >= 4:
                vulns.append(self._build_vuln(
                    name='Potential Race Condition in Business Operation',
                    severity='high',
                    category='Business Logic',
                    description=(
                        f'The endpoint {url} accepted {success_count}/5 concurrent requests '
                        f'without proper serialization. This may allow double-spending, '
                        f'duplicate redemptions, or balance manipulation.'
                    ),
                    impact=(
                        'Double-spending, duplicate coupon redemption, overdraft attacks, '
                        'or inconsistent state from concurrent operations.'
                    ),
                    remediation=(
                        '1. Use database-level locking (SELECT FOR UPDATE). '
                        '2. Implement idempotency keys for financial operations. '
                        '3. Use optimistic concurrency with version checks. '
                        '4. Add request deduplication within a time window.'
                    ),
                    cwe='CWE-362',
                    cvss=7.5,
                    affected_url=url,
                    evidence=f'{success_count}/5 concurrent requests succeeded.',
                ))
                break

        return vulns

    def _test_numeric_overflow(self, target: str) -> list:
        """Test for integer overflow in numeric fields."""
        vulns = []
        base = target.rstrip('/')

        overflow_values = [
            2147483647,      # INT_MAX
            2147483648,      # INT_MAX + 1
            -2147483648,     # INT_MIN
            9999999999999,   # Large number
            1e308,           # Float max
        ]

        for endpoint in CART_ENDPOINTS + PAYMENT_ENDPOINTS:
            url = base + endpoint

            for value in overflow_values:
                payload = {'product_id': 1, 'quantity': value, 'price': 10}
                resp = self._make_request('POST', url, json=payload)
                if not resp:
                    continue

                status = resp.status_code
                body = resp.text or ''

                if status == 500:
                    vulns.append(self._build_vuln(
                        name='Numeric Overflow in Business Field',
                        severity='medium',
                        category='Business Logic',
                        description=(
                            f'The endpoint {url} crashes (HTTP 500) when receiving an '
                            f'extreme numeric value ({value}), indicating missing input '
                            f'validation that could lead to integer overflow.'
                        ),
                        impact=(
                            'DoS via crash, integer wraparound leading to negative totals, '
                            'or unexpected behavior from overflow values.'
                        ),
                        remediation=(
                            '1. Validate numeric inputs against reasonable ranges. '
                            '2. Use appropriate data types (e.g., decimal for currency). '
                            '3. Catch and handle overflow exceptions gracefully.'
                        ),
                        cwe='CWE-190',
                        cvss=5.3,
                        affected_url=url,
                        evidence=f'Value {value} caused HTTP 500.',
                    ))
                    return vulns

                if status in (200, 201):
                    try:
                        data = json.loads(body)
                        total = data.get('total', data.get('amount'))
                        if total is not None and float(total) < 0:
                            vulns.append(self._build_vuln(
                                name='Integer Overflow — Negative Result',
                                severity='high',
                                category='Business Logic',
                                description=(
                                    f'The endpoint {url} accepted extreme value {value} '
                                    f'and produced a negative total ({total}), indicating '
                                    f'integer overflow.'
                                ),
                                impact='Financial manipulation through integer overflow.',
                                remediation=(
                                    '1. Use BigDecimal/Decimal types for financial calculations. '
                                    '2. Validate input ranges before computation.'
                                ),
                                cwe='CWE-190',
                                cvss=8.0,
                                affected_url=url,
                                evidence=f'Input: {value}, Output total: {total}',
                            ))
                            return vulns
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass

        return vulns
