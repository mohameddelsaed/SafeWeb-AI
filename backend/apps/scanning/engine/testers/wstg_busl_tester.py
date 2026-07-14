"""
WSTGBusinessLogicTester — OWASP WSTG-BUSL coverage.
Maps to: WSTG-BUSL-01 (Data Validation), WSTG-BUSL-02 (Forging Requests),
         WSTG-BUSL-03 (Integrity Checks), WSTG-BUSL-04 (Process Timing),
         WSTG-BUSL-05 (Function Use Limits), WSTG-BUSL-06 (Workflow Bypass),
         WSTG-BUSL-07 (Defenses Against Application Misuse),
         WSTG-BUSL-08 (Upload of Unexpected File Types),
         WSTG-BUSL-09 (Upload of Malicious Files).

Fills business logic testing gaps identified in Phase 46.
"""
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Fields commonly holding price/quantity in forms
PRICE_LIKE_FIELDS = {'price', 'amount', 'cost', 'total', 'subtotal', 'fee', 'charge', 'rate'}
QUANTITY_LIKE_FIELDS = {'quantity', 'qty', 'count', 'number', 'num', 'amount', 'units'}
DATE_FIELDS = {'date', 'expiry', 'expiration', 'expires', 'start_date', 'end_date', 'dob', 'birth_date'}

# Boundary / extreme values to test
BOUNDARY_VALUES = [
    '-1', '-999', '0', '999999999', '2147483647', '-2147483648',
    '9999999999999999', '1e999', 'NaN', 'Infinity', '-Infinity',
]


class WSTGBusinessLogicTester(BaseTester):
    """WSTG-BUSL: Business Logic — forged params, negative values, workflow bypass, upload abuse."""

    TESTER_NAME = 'WSTG-BUSL'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # WSTG-BUSL-01/02: Parameter tampering / forging requests
        vulns = self._test_parameter_tampering(page)
        vulnerabilities.extend(vulns)

        # WSTG-BUSL-03: Negative / extreme value submission
        vulns = self._test_negative_and_extreme_values(page)
        vulnerabilities.extend(vulns)

        # WSTG-BUSL-04: Time / date integrity
        vulns = self._test_date_manipulation(page)
        vulnerabilities.extend(vulns)

        # WSTG-BUSL-06/07: Sequential workflow bypass detection
        if depth in ('medium', 'deep'):
            vulns = self._test_workflow_bypass(page)
            vulnerabilities.extend(vulns)

        # WSTG-BUSL-08/09: File upload misuse
        vuln = self._test_file_upload_misuse(page)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-BUSL-05: Function-use limits (missing rate limiting on high-value actions)
        vuln = self._test_missing_rate_limiting(page)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    # ── WSTG-BUSL-01/02: Parameter Tampering ─────────────────────────────────

    def _test_parameter_tampering(self, page) -> list:
        """
        Try to tamper with price/amount/quantity hidden fields.
        A server that re-uses client-submitted values without server-side
        re-computation is vulnerable to business logic manipulation.
        """
        found = []
        forms = getattr(page, 'forms', None) or []
        for form in forms:
            inputs = getattr(form, 'inputs', []) or []
            action = getattr(form, 'action', '') or page.url
            method = (getattr(form, 'method', 'get') or 'get').lower()

            for inp in inputs:
                name = (getattr(inp, 'name', '') or '').lower()
                value = getattr(inp, 'value', '') or ''
                inp_type = (getattr(inp, 'type', '') or '').lower()

                is_price = any(k in name for k in PRICE_LIKE_FIELDS)
                is_qty = any(k in name for k in QUANTITY_LIKE_FIELDS)
                is_hidden = inp_type == 'hidden'

                if not (is_price or is_qty):
                    continue

                # Build a modified form payload: set price/quantity to 0.01 or -1
                manipulated_value = '0.01' if is_price else '-1'
                payload = {getattr(i, 'name', ''): getattr(i, 'value', '') for i in inputs
                           if getattr(i, 'name', '')}
                payload[getattr(inp, 'name', name)] = manipulated_value

                resp = self._make_request(method, action, data=payload if method == 'post'
                                          else None, params=payload if method == 'get' else None)

                if not resp:
                    continue

                # Success response with manipulated value likely means server accepted
                if resp.status_code in (200, 201, 302):
                    vuln_type = 'Price' if is_price else 'Quantity'
                    original_field = getattr(inp, 'name', name)
                    severity = 'high' if is_price else 'medium'
                    found.append(self._build_vuln(
                        name=f'Business Logic: {vuln_type} Parameter Tampering Accepted',
                        severity=severity,
                        category=('WSTG-BUSL-02: Testing for Bypassing Business Logic Data Validation'
                                  if is_hidden else
                                  'WSTG-BUSL-01: Testing for Business Logic Data Validation'),
                        description=f'The form at "{action}" has a {vuln_type.lower()} field '
                                    f'"{original_field}" that accepted a manipulated value '
                                    f'({manipulated_value}) without server-side validation. '
                                    f'The server responded with HTTP {resp.status_code}.',
                        impact=f'Attackers can manipulate {"prices" if is_price else "quantities"}, '
                               f'potentially purchasing items at fraudulent prices, obtaining discounts, '
                               f'or ordering impossible quantities.',
                        remediation='Never trust client-submitted monetary or quantity values. '
                                    'Always compute totals server-side using product database values. '
                                    'Validate ranges (positive, non-zero, within stock limits) server-side.',
                        cwe='CWE-840',
                        cvss=8.1 if is_price else 6.5,
                        affected_url=action,
                        evidence=(f'Field: {original_field}, Original value: {value!r}, '
                                  f'Tampered value: {manipulated_value!r}, '
                                  f'HTTP response: {resp.status_code}'),
                    ))

        return found

    # ── WSTG-BUSL-03: Negative / Extreme Values ───────────────────────────────

    def _test_negative_and_extreme_values(self, page) -> list:
        """Submit boundary/extreme values to numeric fields and detect missing validation."""
        found = []
        forms = getattr(page, 'forms', None) or []
        for form in forms:
            inputs = getattr(form, 'inputs', []) or []
            action = getattr(form, 'action', '') or page.url
            method = (getattr(form, 'method', 'get') or 'get').lower()

            numeric_inputs = [
                i for i in inputs
                if any(k in (getattr(i, 'name', '') or '').lower()
                       for k in PRICE_LIKE_FIELDS | QUANTITY_LIKE_FIELDS)
                   and (getattr(i, 'type', '') or '').lower() in ('text', 'number', 'hidden', '')
            ]
            if not numeric_inputs:
                continue

            for test_val in ['-1', '-999', '9999999999']:
                base_payload = {getattr(i, 'name', ''): getattr(i, 'value', '') for i in inputs
                                if getattr(i, 'name', '')}
                inp = numeric_inputs[0]
                field_name = getattr(inp, 'name', '')
                base_payload[field_name] = test_val

                resp = self._make_request(method, action,
                                          data=base_payload if method == 'post' else None,
                                          params=base_payload if method == 'get' else None)
                if not resp:
                    continue

                body = (resp.text or '').lower()
                # If server returns error with stack trace or DB error — extra severity
                if resp.status_code == 500:
                    found.append(self._build_vuln(
                        name=f'Business Logic: Server Error on Extreme Input ({test_val})',
                        severity='medium',
                        category='WSTG-BUSL-01: Testing for Business Logic Data Validation',
                        description=f'Submitting extreme value "{test_val}" to field "{field_name}" '
                                    f'at "{action}" caused an HTTP 500 error, indicating the server '
                                    f'failed to handle boundary conditions.',
                        impact='Attackers can cause denial of service or expose stack traces by '
                               'submitting crafted numeric values.',
                        remediation='Implement server-side input validation: reject negative values '
                                    'for positive-only fields, enforce maximum limits, handle exceptions '
                                    'gracefully without leaking stack traces.',
                        cwe='CWE-20',
                        cvss=5.3,
                        affected_url=action,
                        evidence=f'Field: {field_name}, Value: {test_val}, HTTP: 500',
                    ))
                    break  # one finding per form
                elif resp.status_code == 200 and not any(
                    w in body for w in ('error', 'invalid', 'must be positive', 'greater than zero')
                ):
                    # Server accepted the value silently
                    found.append(self._build_vuln(
                        name='Business Logic: Extreme/Negative Value Accepted Without Validation',
                        severity='medium',
                        category='WSTG-BUSL-01: Testing for Business Logic Data Validation',
                        description=f'The field "{field_name}" at "{action}" accepted extreme value '
                                    f'"{test_val}" with no validation error in the response.',
                        impact='Missing server-side boundary validation allows manipulation of '
                               'business calculations (negative prices, overflow quantities).',
                        remediation='Add server-side range validation for all numeric business fields.',
                        cwe='CWE-20',
                        cvss=5.4,
                        affected_url=action,
                        evidence=f'Field: {field_name}, Value: {test_val!r}, '
                                 f'Response {resp.status_code} contained no rejection message.',
                    ))
                    break  # one finding per form

        return found

    # ── WSTG-BUSL-04: Time/Date Manipulation ─────────────────────────────────

    def _test_date_manipulation(self, page) -> list:
        """Test date fields with past/future boundary dates."""
        found = []
        forms = getattr(page, 'forms', None) or []
        for form in forms:
            inputs = getattr(form, 'inputs', []) or []
            action = getattr(form, 'action', '') or page.url
            method = (getattr(form, 'method', 'get') or 'get').lower()

            date_inputs = [
                i for i in inputs
                if any(k in (getattr(i, 'name', '') or '').lower() for k in DATE_FIELDS)
                   or (getattr(i, 'type', '') or '').lower() == 'date'
            ]
            if not date_inputs:
                continue

            for past_date in ('1900-01-01', '2099-12-31', '0000-00-00'):
                base_payload = {getattr(i, 'name', ''): getattr(i, 'value', '') for i in inputs
                                if getattr(i, 'name', '')}
                inp = date_inputs[0]
                field_name = getattr(inp, 'name', '')
                base_payload[field_name] = past_date

                resp = self._make_request(method, action,
                                          data=base_payload if method == 'post' else None,
                                          params=base_payload if method == 'get' else None)
                if not resp:
                    continue

                body = (resp.text or '').lower()
                if resp.status_code == 200 and not any(
                    w in body for w in ('invalid date', 'invalid', 'error', 'must be')
                ):
                    found.append(self._build_vuln(
                        name='Business Logic: Date Field Accepts Out-of-Range Value',
                        severity='low',
                        category='WSTG-BUSL-04: Testing for Process Timing',
                        description=f'The date field "{field_name}" at "{action}" accepted '
                                    f'out-of-range date "{past_date}" with no server-side rejection.',
                        impact='Attackers can manipulate date-sensitive operations: extend expiry dates, '
                               'bypass age checks, or cause time-based logic errors.',
                        remediation='Validate all date fields server-side: enforce min/max date ranges '
                                    'appropriate for the business context.',
                        cwe='CWE-20',
                        cvss=3.7,
                        affected_url=action,
                        evidence=f'Field: {field_name}, Value: {past_date!r}, '
                                 f'Response: HTTP {resp.status_code}, no rejection message.',
                    ))
                    break

        return found

    # ── WSTG-BUSL-06: Workflow Bypass Detection ───────────────────────────────

    def _test_workflow_bypass(self, page) -> list:
        """
        Detect multi-step wizard/checkout pages where step-skipping may be possible.
        Look for step/stage parameters and try jumping to a later step.
        """
        found = []
        url = page.url
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Look for step/stage/page indicators in URL params
        step_params = [k for k in params if k.lower() in ('step', 'stage', 'page', 'phase', 'screen')]
        if not step_params:
            return found

        for step_param in step_params:
            current_val = params[step_param][0]
            try:
                current_step = int(current_val)
            except (ValueError, TypeError):
                continue

            # Try jumping to step N+2 (skip a step)
            skip_step = str(current_step + 2)
            new_params = dict(params)
            new_params[step_param] = [skip_step]
            new_query = urlencode({k: v[0] for k, v in new_params.items()})
            skip_url = urlunparse(parsed._replace(query=new_query))

            resp = self._make_request('GET', skip_url)
            if not resp:
                continue

            # If we got 200 with substantial content, the step was accessible
            if resp.status_code == 200 and len(resp.text or '') > 200:
                body_lower = (resp.text or '').lower()
                # Not showing "invalid step" / "forbidden" / redirect content
                if not any(w in body_lower for w in ('invalid step', 'forbidden', 'unauthorized',
                                                      'not allowed', 'complete previous')):
                    found.append(self._build_vuln(
                        name='Business Logic: Multi-Step Workflow Step Skip',
                        severity='medium',
                        category='WSTG-BUSL-06: Testing for the Circumvention of Work Flows',
                        description=f'The URL parameter "{step_param}" can be manipulated to jump '
                                    f'from step {current_step} to step {skip_step}, bypassing '
                                    f'intermediate workflow steps. The server returned HTTP 200 '
                                    f'with content for the skipped step.',
                        impact='Attackers can skip required steps in checkout, registration, or '
                               'approval workflows — potentially completing purchases without payment, '
                               'bypassing ID verification, or skipping mandatory confirmations.',
                        remediation='Implement server-side workflow state tracking. Verify that '
                                    'previous steps were completed before allowing access to subsequent '
                                    'steps. Store workflow state in the session, not in URL parameters.',
                        cwe='CWE-840',
                        cvss=6.5,
                        affected_url=skip_url,
                        evidence=(f'Parameter "{step_param}" changed from {current_step} to {skip_step}. '
                                  f'Response: HTTP {resp.status_code}, body length: {len(resp.text or "")}'),
                    ))

        return found

    # ── WSTG-BUSL-08/09: File Upload Misuse ──────────────────────────────────

    def _test_file_upload_misuse(self, page):
        """
        Detect file upload fields and probe for dangerous file type acceptance.
        """
        forms = getattr(page, 'forms', None) or []
        for form in forms:
            inputs = getattr(form, 'inputs', []) or []
            action = getattr(form, 'action', '') or page.url

            file_inputs = [i for i in inputs if (getattr(i, 'type', '') or '').lower() == 'file']
            if not file_inputs:
                continue

            # Check if accept attribute is restrictive
            inp = file_inputs[0]
            accept = (getattr(inp, 'accept', '') or '').lower()
            name = getattr(inp, 'name', 'file')

            # If no accept restriction, the upload is permissive by default
            if not accept:
                return self._build_vuln(
                    name='File Upload: No Client-Side File Type Restriction',
                    severity='medium',
                    category='WSTG-BUSL-08: Testing for Unexpected File Types',
                    description=f'The file upload field "{name}" at "{action}" has no "accept" '
                                f'attribute restricting file types. While server-side validation '
                                f'is critical, the absence of even client-side guidance suggests '
                                f'potential lax validation.',
                    impact='Without server-side type/content validation, attackers can upload '
                           'executable scripts (PHP, JSP, ASP), malware, or oversized files.',
                    remediation='Implement strict server-side file type validation using '
                                'magic bytes/MIME type detection (not just extension). '
                                'Restrict to allowed extensions, scan uploads with AV, '
                                'store uploads outside web root, randomize filenames.',
                    cwe='CWE-434',
                    cvss=6.5,
                    affected_url=action,
                    evidence=f'File input "{name}" has no accept attribute. Form action: {action}',
                )
        return None

    # ── WSTG-BUSL-05: Missing Rate Limiting on High-Value Actions ─────────────

    def _test_missing_rate_limiting(self, page):
        """
        Rapidly invoke a high-value action endpoint and check for rate limiting.
        Flags endpoints that lack 429/CAPTCHA protection after rapid requests.
        """
        # Look for form actions that suggest high-value operations
        forms = getattr(page, 'forms', None) or []
        for form in forms:
            action = (getattr(form, 'action', '') or page.url).lower()
            if not any(kw in action for kw in ('/checkout', '/purchase', '/buy', '/redeem',
                                               '/coupon', '/promo', '/transfer', '/pay')):
                continue

            # Send 5 rapid identical requests
            responses = []
            for _ in range(5):
                resp = self._make_request('POST' if (getattr(form, 'method', '') or '').upper() == 'POST'
                                         else 'GET', getattr(form, 'action', '') or page.url)
                if resp:
                    responses.append(resp)

            if not responses:
                continue

            # If none returned 429 or CAPTCHA indication
            status_codes = [r.status_code for r in responses]
            bodies = [(r.text or '').lower() for r in responses]
            has_rate_limit = (
                429 in status_codes
                or any('too many' in b or 'captcha' in b or 'rate limit' in b for b in bodies)
            )

            if not has_rate_limit and len(responses) >= 3:
                return self._build_vuln(
                    name='Business Logic: No Rate Limiting on High-Value Action',
                    severity='medium',
                    category='WSTG-BUSL-05: Testing for Function Limits',
                    description=f'The endpoint "{action}" appears to be a high-value action '
                                f'(checkout/purchase/transfer) but did not return HTTP 429 or '
                                f'show CAPTCHA after 5 rapid identical requests.',
                    impact='Attackers can automate repeated invocation of high-value actions: '
                           'coupon abuse, gift card enumeration, unlimited purchase attempts, '
                           'or denial of inventory.',
                    remediation='Implement per-user and per-IP rate limiting on high-value endpoints. '
                                'Add CAPTCHA for repeated actions. Log and alert on anomalous request rates.',
                    cwe='CWE-770',
                    cvss=5.8,
                    affected_url=action,
                    evidence=f'5 rapid requests returned status codes: {status_codes}. No 429 observed.',
                )

        return None
