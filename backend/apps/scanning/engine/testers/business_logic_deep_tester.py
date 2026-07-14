"""
Business Logic Deep Tester — Wraps the Phase 31 logic engines into
the BaseTester interface for automated business logic testing.

Delegates to PaymentFlowTester, AuthFlowTester, StateMachineTester,
and RateLimitTester based on page characteristics.
"""
import logging

from apps.scanning.engine.testers.base_tester import BaseTester
from apps.scanning.engine.logic.payment_tester import PaymentFlowTester
from apps.scanning.engine.logic.auth_flow_tester import AuthFlowTester
from apps.scanning.engine.logic.state_machine import StateMachineTester
from apps.scanning.engine.logic.rate_limit_tester import RateLimitTester

logger = logging.getLogger(__name__)

# ── Severity → CVSS ─────────────────────────────────────────────────────────
_SEVERITY_CVSS = {
    'critical': 9.8,
    'high': 7.5,
    'medium': 5.3,
    'low': 3.1,
    'info': 0.0,
}

# ── Technique → CWE ─────────────────────────────────────────────────────────
_TECHNIQUE_CWE = {
    # Payment
    'price_manipulation': 'CWE-472',
    'quantity_manipulation': 'CWE-472',
    'currency_confusion': 'CWE-472',
    'coupon_abuse': 'CWE-472',
    'payment_race': 'CWE-362',
    # Auth flow
    'account_enumeration': 'CWE-204',
    'otp_bypass': 'CWE-287',
    'reset_token_predictable': 'CWE-330',
    'reset_token_weak': 'CWE-330',
    'registration_abuse': 'CWE-287',
    'host_header_reset': 'CWE-20',
    # State machine
    'skip_step': 'CWE-841',
    'direct_access': 'CWE-841',
    'state_transition': 'CWE-841',
    'backward_navigation': 'CWE-841',
    # Rate limit
    'no_rate_limit': 'CWE-770',
    'header_bypass': 'CWE-770',
    'variation_bypass': 'CWE-770',
    'version_bypass': 'CWE-770',
}

# ── Technique → category ─────────────────────────────────────────────────────
_TECHNIQUE_CATEGORY = {
    'price_manipulation': 'business_logic',
    'quantity_manipulation': 'business_logic',
    'currency_confusion': 'business_logic',
    'coupon_abuse': 'business_logic',
    'payment_race': 'business_logic',
    'account_enumeration': 'authentication',
    'otp_bypass': 'authentication',
    'reset_token_predictable': 'authentication',
    'reset_token_weak': 'authentication',
    'registration_abuse': 'authentication',
    'host_header_reset': 'authentication',
    'skip_step': 'business_logic',
    'direct_access': 'business_logic',
    'state_transition': 'business_logic',
    'backward_navigation': 'business_logic',
    'no_rate_limit': 'rate_limiting',
    'header_bypass': 'rate_limiting',
    'variation_bypass': 'rate_limiting',
    'version_bypass': 'rate_limiting',
}

# ── Keywords in URLs that suggest relevant testing ───────────────────────────
_PAYMENT_KEYWORDS = {'cart', 'checkout', 'payment', 'pay', 'order', 'purchase', 'billing', 'basket'}
_AUTH_KEYWORDS = {'login', 'signin', 'auth', 'register', 'signup', 'password', 'forgot', 'reset', 'otp', 'verify', '2fa', 'mfa'}
_WORKFLOW_KEYWORDS = {'step', 'checkout', 'onboarding', 'setup', 'wizard', 'flow', 'kyc'}


class BusinessLogicDeepTester(BaseTester):
    """Deep business logic testing using Phase 31 engines."""

    TESTER_NAME = 'Business Logic Deep'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '')

        if not url:
            return vulns

        url_lower = url.lower()
        body_lower = body.lower() if body else ''

        # Determine which engines to run based on page content
        run_payment = self._should_run(url_lower, body_lower, _PAYMENT_KEYWORDS)
        run_auth = self._should_run(url_lower, body_lower, _AUTH_KEYWORDS)
        run_workflow = self._should_run(url_lower, body_lower, _WORKFLOW_KEYWORDS)

        # Always run rate limit on auth-like pages
        run_rate_limit = run_auth

        # In deep mode, run all engines regardless
        if depth == 'deep':
            run_payment = run_auth = run_workflow = run_rate_limit = True

        if run_payment:
            payment = PaymentFlowTester(self._make_request)
            for finding in payment.test(url, body, depth):
                vulns.append(self._finding_to_vuln(finding, url))

        if run_auth:
            auth = AuthFlowTester(self._make_request)
            for finding in auth.test(url, body, depth):
                vulns.append(self._finding_to_vuln(finding, url))

        if run_workflow:
            state = StateMachineTester(self._make_request)
            for finding in state.test(url, body, depth):
                vulns.append(self._finding_to_vuln(finding, url))

        if run_rate_limit:
            rate = RateLimitTester(self._make_request)
            for finding in rate.test(url, body, depth):
                vulns.append(self._finding_to_vuln(finding, url))

        return vulns

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _should_run(url_lower: str, body_lower: str, keywords: set) -> bool:
        return any(kw in url_lower or kw in body_lower for kw in keywords)

    def _finding_to_vuln(self, finding: dict, url: str) -> dict:
        technique = finding.get('technique', '')
        detail = finding.get('detail', '')
        severity = finding.get('severity', 'info')
        evidence = finding.get('evidence', '')
        category = _TECHNIQUE_CATEGORY.get(technique, 'business_logic')

        return self._build_vuln(
            name=f'Business Logic: {detail}',
            severity=severity,
            category=category,
            description=f'Business logic testing — {detail}',
            impact=self._impact_for_technique(technique),
            remediation=self._remediation_for_technique(technique),
            cwe=_TECHNIQUE_CWE.get(technique, 'CWE-840'),
            cvss=_SEVERITY_CVSS.get(severity, 0.0),
            affected_url=url,
            evidence=evidence,
        )

    @staticmethod
    def _impact_for_technique(technique: str) -> str:
        impacts = {
            'business_logic': 'Financial loss, order manipulation, fraud',
            'authentication': 'Account takeover, unauthorized access, credential theft',
            'rate_limiting': 'Brute force attacks, credential stuffing, denial of service',
        }
        category = _TECHNIQUE_CATEGORY.get(technique, 'business_logic')
        return impacts.get(category, 'Business logic flaw confirmed')

    @staticmethod
    def _remediation_for_technique(technique: str) -> str:
        remediations = {
            'business_logic': 'Validate all business-critical values server-side. Enforce workflow sequences. Use server-side state tracking.',
            'authentication': 'Use generic error messages. Implement strong token generation. Enforce rate limits on auth endpoints.',
            'rate_limiting': 'Implement proper rate limiting based on authenticated user, not just IP. Use sliding window counters.',
        }
        category = _TECHNIQUE_CATEGORY.get(technique, 'business_logic')
        return remediations.get(category, 'Review business logic and add server-side validation.')
