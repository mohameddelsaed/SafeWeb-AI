"""
State Machine Testing Engine — Workflow and state manipulation.

Tests:
  - Skip-step bypass (jump to checkout without payment)
  - Workflow manipulation (edit completed order)
  - State transition abuse
"""
import logging
import json

logger = logging.getLogger(__name__)

# ── Multi-step workflow sequences ────────────────────────────────────────────
CHECKOUT_FLOWS = [
    ['/api/checkout/step1', '/api/checkout/step2', '/api/checkout/step3', '/api/checkout/confirm'],
    ['/api/checkout/cart', '/api/checkout/shipping', '/api/checkout/payment', '/api/checkout/complete'],
    ['/checkout/step/1', '/checkout/step/2', '/checkout/step/3'],
]

ONBOARDING_FLOWS = [
    ['/api/onboarding/step1', '/api/onboarding/step2', '/api/onboarding/complete'],
    ['/api/setup/profile', '/api/setup/preferences', '/api/setup/confirm'],
]

VERIFICATION_FLOWS = [
    ['/api/verify/email', '/api/verify/phone', '/api/verify/complete'],
    ['/api/kyc/step1', '/api/kyc/step2', '/api/kyc/approve'],
]

# ── Order state manipulation payloads ────────────────────────────────────────
STATE_PAYLOADS = [
    {'status': 'completed'},
    {'status': 'approved'},
    {'status': 'paid'},
    {'state': 'shipped'},
    {'state': 'delivered'},
    {'order_status': 'refunded'},
]

ORDER_ENDPOINTS = [
    '/api/orders/{id}',
    '/api/order/{id}',
    '/api/orders/{id}/status',
    '/api/order/{id}/update',
]


class StateMachineTester:
    """
    Test application state machines for logic bypass.

    Usage:
        tester = StateMachineTester(make_request_fn)
        findings = tester.test(url, body, depth='medium')
    """

    def __init__(self, make_request_fn):
        self._request = make_request_fn

    def test(self, url: str, body: str = '', depth: str = 'medium') -> list:
        """
        Run state machine tests.

        Returns list of finding dicts with keys:
            technique, detail, severity, evidence.
        """
        findings = []
        base = url.rstrip('/')

        # 1. Skip-step bypass
        findings.extend(self._test_skip_step(base))

        if depth == 'shallow':
            return findings

        # 2. Direct final step access
        findings.extend(self._test_direct_final_step(base))

        if depth == 'deep':
            # 3. State transition abuse
            findings.extend(self._test_state_transition_abuse(base))

            # 4. Workflow backward navigation
            findings.extend(self._test_backward_navigation(base))

        return findings

    # ── Skip-step bypass ─────────────────────────────────────────────────

    def _test_skip_step(self, base_url: str) -> list:
        """Skip intermediate workflow steps and go to final step."""
        findings = []
        all_flows = CHECKOUT_FLOWS + ONBOARDING_FLOWS + VERIFICATION_FLOWS

        for flow in all_flows:
            if len(flow) < 2:
                continue

            # Try final step directly (skipping all preceding steps)
            final_url = base_url + flow[-1]
            try:
                resp = self._request('POST', final_url, json={'action': 'complete'})
                if not resp:
                    continue
                status = getattr(resp, 'status_code', 0)
                text = getattr(resp, 'text', '')

                if status in (200, 201) and self._looks_like_success(text):
                    findings.append({
                        'technique': 'skip_step',
                        'detail': f'Workflow step skip — final step accessible directly: {flow[-1]}',
                        'severity': 'critical',
                        'evidence': f'POST {flow[-1]} without prior steps → HTTP {status}',
                    })
                    return findings
            except Exception:
                continue
        return findings

    # ── Direct final step access ─────────────────────────────────────────

    def _test_direct_final_step(self, base_url: str) -> list:
        """Access completion/confirmation endpoints directly via GET."""
        findings = []
        completion_paths = [
            '/api/checkout/complete', '/api/checkout/confirm',
            '/api/onboarding/complete', '/api/orders/complete',
            '/api/verify/complete', '/api/kyc/approve',
        ]
        for path in completion_paths:
            url = base_url + path
            try:
                resp = self._request('GET', url)
                if not resp:
                    continue
                status = getattr(resp, 'status_code', 0)
                text = getattr(resp, 'text', '')

                if status == 200 and self._looks_like_success(text):
                    findings.append({
                        'technique': 'direct_access',
                        'detail': f'Completion endpoint accessible via GET: {path}',
                        'severity': 'high',
                        'evidence': f'GET {path} → HTTP {status}',
                    })
                    return findings
            except Exception:
                continue
        return findings

    # ── State transition abuse ───────────────────────────────────────────

    def _test_state_transition_abuse(self, base_url: str) -> list:
        """Attempt to directly set order/entity status."""
        findings = []
        test_ids = ['1', '999', 'test']

        for endpoint_tpl in ORDER_ENDPOINTS:
            for test_id in test_ids:
                endpoint = endpoint_tpl.replace('{id}', test_id)
                url = base_url + endpoint
                for payload in STATE_PAYLOADS:
                    try:
                        resp = self._request('PUT', url, json=payload)
                        if not resp:
                            continue
                        status = getattr(resp, 'status_code', 0)
                        text = getattr(resp, 'text', '')

                        if status == 200 and self._looks_like_success(text):
                            field = list(payload.keys())[0]
                            val = payload[field]
                            findings.append({
                                'technique': 'state_transition',
                                'detail': f'State manipulation: {field}={val} accepted at {endpoint}',
                                'severity': 'critical',
                                'evidence': f'PUT {endpoint} with {json.dumps(payload)} → HTTP {status}',
                            })
                            return findings
                    except Exception:
                        continue
        return findings

    # ── Backward navigation ──────────────────────────────────────────────

    def _test_backward_navigation(self, base_url: str) -> list:
        """Test if completed workflows can be navigated backward."""
        findings = []
        all_flows = CHECKOUT_FLOWS + ONBOARDING_FLOWS

        for flow in all_flows:
            if len(flow) < 3:
                continue

            # Simulate: access final step, then try accessing earlier steps
            final_url = base_url + flow[-1]
            first_url = base_url + flow[0]
            try:
                self._request('POST', final_url, json={'action': 'complete'})
                resp = self._request('POST', first_url, json={'action': 'start'})
                if not resp:
                    continue
                status = getattr(resp, 'status_code', 0)
                text = getattr(resp, 'text', '')

                if status in (200, 201) and self._looks_like_success(text):
                    findings.append({
                        'technique': 'backward_navigation',
                        'detail': f'Backward workflow re-entry after completion: {flow[0]}',
                        'severity': 'high',
                        'evidence': f'POST {flow[0]} after {flow[-1]} → HTTP {status}',
                    })
                    return findings
            except Exception:
                continue
        return findings

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _looks_like_success(text: str) -> bool:
        lower = text.lower()
        indicators = [
            '"success"', '"ok"', '"completed"', '"approved"',
            '"confirmed"', '"status":"success"', '"status": "success"',
            'order confirmed', 'step complete', 'verified',
        ]
        return any(ind in lower for ind in indicators)
