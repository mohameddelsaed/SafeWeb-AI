"""
Verification Engine — Re-confirm high/critical vulnerability findings
using secondary payloads, timing differentials, and response diffing.

Reduces false positives by independently re-testing each finding with
a different payload or technique than the original tester used.

Verification methods:
  - XSS: unique canary reflection check
  - SQLi: SLEEP timing differential (5s vs 0s)
  - SSRF: re-send payload, compare status/length
  - SSTI: different math expression ({{9*9}} → 81)
  - CMDi: re-send, check OS output patterns
  - Open Redirect: different redirect target, check Location header
  - Generic: response diffing (payload vs clean request)
"""
import logging
import re
import time
import uuid
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of a single vulnerability verification attempt."""
    vuln_id: str
    confirmed: bool
    confidence: float                   # 0.0 – 1.0
    confirmation_method: str            # 'secondary_payload' | 'time_diff' | 'response_diff' | 'behavioral'
    evidence: str = ''
    false_positive_score: float = 0.0   # 1.0 - confidence

    def __post_init__(self):
        self.false_positive_score = round(1.0 - self.confidence, 3)


class VerificationEngine:
    """Re-confirm vulnerability findings with independent secondary checks."""

    REQUEST_TIMEOUT = 10

    # Vuln-category → verifier method mapping
    _VERIFIERS = {
        'xss': '_verify_xss',
        'cross-site scripting': '_verify_xss',
        'sqli': '_verify_sqli',
        'sql injection': '_verify_sqli',
        'ssrf': '_verify_ssrf',
        'server-side request forgery': '_verify_ssrf',
        'ssti': '_verify_ssti',
        'server-side template injection': '_verify_ssti',
        'cmdi': '_verify_cmdi',
        'command injection': '_verify_cmdi',
        'os command injection': '_verify_cmdi',
        'open redirect': '_verify_open_redirect',
        'openredirect': '_verify_open_redirect',
    }

    def __init__(self, http_client=None):
        if http_client:
            self.session = http_client
        else:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'SafeWeb AI Scanner/2.0 (Verification)',
            })
            self.session.verify = False

    # ── Public API ────────────────────────────────────────────────────────

    async def verify_all(self, vulns: list, depth: str = 'medium') -> list[VerificationResult]:
        """Verify high/critical findings (skip medium/low — too slow).

        Returns list of VerificationResult objects.
        """
        import asyncio
        from apps.scanning.engine.async_engine import AsyncTaskRunner
        
        runner = AsyncTaskRunner(max_concurrency=20, default_timeout=20.0)
        for vuln in vulns:
            severity = vuln.get('severity', 'info')
            if severity not in ('critical', 'high'):
                continue
            vuln_id = vuln.get('_id', '')
            runner.add(vuln_id, self._verify_single, args=(vuln,))
            
        task_results = await runner.run()
        results = []
        for key, res in task_results.items():
            if res.result:
                results.append(res.result)
            else:
                results.append(VerificationResult(
                    vuln_id=key,
                    confirmed=False,
                    confidence=0.3,
                    confirmation_method='error',
                    evidence=f'Verification error/timeout: {res.error}',
                ))
        return results

    # ── Internal dispatch ─────────────────────────────────────────────────

    def _verify_single(self, vuln: dict) -> VerificationResult:
        """Dispatch to the correct verifier based on category/name."""
        category = (vuln.get('category', '') or '').lower().strip()
        name = (vuln.get('name', '') or '').lower().strip()

        # Find matching verifier
        for key, method_name in self._VERIFIERS.items():
            if key in category or key in name:
                method = getattr(self, method_name)
                return method(vuln)

        # Fallback
        return self._verify_generic(vuln)

    # ── Request helpers ───────────────────────────────────────────────────

    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make an HTTP request with timeout and error handling."""
        kwargs.setdefault('timeout', self.REQUEST_TIMEOUT)
        kwargs.setdefault('allow_redirects', False)
        kwargs.setdefault('verify', False)
        try:
            resp = self.session.request(method, url, **kwargs)
            return resp
        except Exception as exc:
            logger.debug(f'Verification request failed: {method} {url}: {exc}')
            return None

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Replace or add a parameter value in the URL query string."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return f'{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}'

    def _extract_param(self, vuln: dict) -> Optional[str]:
        """Try to extract the vulnerable parameter name from evidence/URL."""
        evidence = vuln.get('evidence', '') or ''
        affected_url = vuln.get('affected_url', '') or ''

        # Pattern: "parameter: xxx" or "param=xxx"
        m = re.search(r'parameter[:\s]+["\']?(\w+)', evidence, re.I)
        if m:
            return m.group(1)
        m = re.search(r'param[=:\s]+["\']?(\w+)', evidence, re.I)
        if m:
            return m.group(1)

        # Fall back to first query param
        parsed = urlparse(affected_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if params:
            return next(iter(params))
        return None

    # ── XSS Verification ─────────────────────────────────────────────────

    def _verify_xss(self, vuln: dict) -> VerificationResult:
        """Send a unique XSS canary and check for unescaped reflection."""
        vuln_id = vuln.get('_id', '')
        affected_url = vuln.get('affected_url', '')
        param = self._extract_param(vuln)

        canary = f'swv{uuid.uuid4().hex[:8]}'
        xss_payload = f'<img src=x onerror={canary}>'

        if param and affected_url:
            test_url = self._inject_param(affected_url, param, xss_payload)
            resp = self._safe_request('GET', test_url)
            if resp and canary in (resp.text or ''):
                # Check if reflected unescaped
                if f'onerror={canary}' in resp.text:
                    return VerificationResult(
                        vuln_id=vuln_id, confirmed=True, confidence=0.95,
                        confirmation_method='secondary_payload',
                        evidence=f'Canary "{canary}" reflected unescaped in response',
                    )
                return VerificationResult(
                    vuln_id=vuln_id, confirmed=True, confidence=0.7,
                    confirmation_method='secondary_payload',
                    evidence=f'Canary "{canary}" found in response (may be escaped)',
                )

        return VerificationResult(
            vuln_id=vuln_id, confirmed=False, confidence=0.4,
            confirmation_method='secondary_payload',
            evidence='Canary not reflected or parameter unknown',
        )

    # ── SQLi Verification ────────────────────────────────────────────────

    def _verify_sqli(self, vuln: dict) -> VerificationResult:
        """Time-based blind: SLEEP(5) vs SLEEP(0) differential."""
        vuln_id = vuln.get('_id', '')
        affected_url = vuln.get('affected_url', '')
        param = self._extract_param(vuln)

        if not param or not affected_url:
            return self._verify_generic(vuln)

        # Baseline: SLEEP(0)
        url_fast = self._inject_param(affected_url, param, "1' AND SLEEP(0)-- -")
        t0 = time.monotonic()
        self._safe_request('GET', url_fast)
        time_fast = time.monotonic() - t0

        # Payload: SLEEP(5)
        url_slow = self._inject_param(affected_url, param, "1' AND SLEEP(5)-- -")
        t0 = time.monotonic()
        resp_slow = self._safe_request('GET', url_slow)
        time_slow = time.monotonic() - t0

        delta = time_slow - time_fast
        if delta >= 4.0:
            return VerificationResult(
                vuln_id=vuln_id, confirmed=True, confidence=0.95,
                confirmation_method='time_diff',
                evidence=f'SLEEP timing confirmed: delta={delta:.2f}s (fast={time_fast:.2f}s, slow={time_slow:.2f}s)',
            )

        # Fallback: check for SQL error strings from original evidence
        vuln.get('evidence', '') or ''
        error_patterns = [
            r'sql syntax', r'mysql', r'ORA-\d{5}', r'postgresql',
            r'sqlite3?\.', r'unclosed quotation', r'quoted string not properly terminated',
        ]
        if resp_slow and any(re.search(p, resp_slow.text or '', re.I) for p in error_patterns):
            return VerificationResult(
                vuln_id=vuln_id, confirmed=True, confidence=0.8,
                confirmation_method='response_diff',
                evidence='SQL error strings detected in secondary payload response',
            )

        return VerificationResult(
            vuln_id=vuln_id, confirmed=False, confidence=0.3,
            confirmation_method='time_diff',
            evidence=f'SLEEP delta insufficient: {delta:.2f}s',
        )

    # ── SSRF Verification ────────────────────────────────────────────────

    def _verify_ssrf(self, vuln: dict) -> VerificationResult:
        """Re-send the SSRF payload and compare status/length."""
        vuln_id = vuln.get('_id', '')
        affected_url = vuln.get('affected_url', '')
        param = self._extract_param(vuln)

        if not param or not affected_url:
            return self._verify_generic(vuln)

        # Re-send with a known internal target
        ssrf_payload = 'http://169.254.169.254/latest/meta-data/'
        test_url = self._inject_param(affected_url, param, ssrf_payload)
        resp = self._safe_request('GET', test_url)

        # Compare with clean request
        clean_url = self._inject_param(affected_url, param, 'https://example.com')
        resp_clean = self._safe_request('GET', clean_url)

        if resp and resp_clean:
            status_match = resp.status_code == resp_clean.status_code
            len_diff = abs(len(resp.text or '') - len(resp_clean.text or ''))

            # If SSRF payload returns different content
            if not status_match or len_diff > 200:
                return VerificationResult(
                    vuln_id=vuln_id, confirmed=True, confidence=0.85,
                    confirmation_method='response_diff',
                    evidence=f'SSRF verified: status={resp.status_code} vs {resp_clean.status_code}, '
                             f'length delta={len_diff}',
                )

        return VerificationResult(
            vuln_id=vuln_id, confirmed=False, confidence=0.35,
            confirmation_method='response_diff',
            evidence='SSRF re-send showed no significant difference',
        )

    # ── SSTI Verification ────────────────────────────────────────────────

    def _verify_ssti(self, vuln: dict) -> VerificationResult:
        """Send a different math expression and check for evaluation."""
        vuln_id = vuln.get('_id', '')
        affected_url = vuln.get('affected_url', '')
        param = self._extract_param(vuln)

        if not param or not affected_url:
            return self._verify_generic(vuln)

        # Try multiple template syntaxes
        tests = [
            ('{{9*9}}', '81'),
            ('${13*7}', '91'),
            ('<%= 11*11 %>', '121'),
            ('#{17*3}', '51'),
        ]

        for payload, expected in tests:
            test_url = self._inject_param(affected_url, param, payload)
            resp = self._safe_request('GET', test_url)
            if resp and expected in (resp.text or ''):
                return VerificationResult(
                    vuln_id=vuln_id, confirmed=True, confidence=0.95,
                    confirmation_method='secondary_payload',
                    evidence=f'SSTI confirmed: {payload} → {expected} found in response',
                )

        return VerificationResult(
            vuln_id=vuln_id, confirmed=False, confidence=0.3,
            confirmation_method='secondary_payload',
            evidence='No template expression evaluated in response',
        )

    # ── Command Injection Verification ───────────────────────────────────

    def _verify_cmdi(self, vuln: dict) -> VerificationResult:
        """Re-send payload and check for OS output patterns."""
        vuln_id = vuln.get('_id', '')
        affected_url = vuln.get('affected_url', '')
        param = self._extract_param(vuln)

        if not param or not affected_url:
            return self._verify_generic(vuln)

        # Safe command that produces recognizable output
        cmdi_payloads = [
            (';echo safeweb_verify_cmdi', 'safeweb_verify_cmdi'),
            ('|echo safeweb_verify_cmdi', 'safeweb_verify_cmdi'),
            ('`echo safeweb_verify_cmdi`', 'safeweb_verify_cmdi'),
        ]

        for payload, marker in cmdi_payloads:
            test_url = self._inject_param(affected_url, param, payload)
            resp = self._safe_request('GET', test_url)
            if resp and marker in (resp.text or ''):
                return VerificationResult(
                    vuln_id=vuln_id, confirmed=True, confidence=0.95,
                    confirmation_method='secondary_payload',
                    evidence=f'CMDi confirmed: marker "{marker}" found in response',
                )

        # Check for uid= pattern (Linux)
        test_url = self._inject_param(affected_url, param, ';id')
        resp = self._safe_request('GET', test_url)
        if resp and re.search(r'uid=\d+', resp.text or ''):
            return VerificationResult(
                vuln_id=vuln_id, confirmed=True, confidence=0.9,
                confirmation_method='secondary_payload',
                evidence='uid= pattern found in response from ;id payload',
            )

        return VerificationResult(
            vuln_id=vuln_id, confirmed=False, confidence=0.3,
            confirmation_method='secondary_payload',
            evidence='No command output patterns detected',
        )

    # ── Open Redirect Verification ───────────────────────────────────────

    def _verify_open_redirect(self, vuln: dict) -> VerificationResult:
        """Send a different redirect target and check Location header."""
        vuln_id = vuln.get('_id', '')
        affected_url = vuln.get('affected_url', '')
        param = self._extract_param(vuln)

        if not param or not affected_url:
            return self._verify_generic(vuln)

        redirect_target = 'https://safeweb-verify-redirect.example.com'
        test_url = self._inject_param(affected_url, param, redirect_target)
        resp = self._safe_request('GET', test_url)

        if resp and resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get('Location', '')
            if 'safeweb-verify-redirect' in location:
                return VerificationResult(
                    vuln_id=vuln_id, confirmed=True, confidence=0.95,
                    confirmation_method='secondary_payload',
                    evidence=f'Open redirect confirmed: Location={location}',
                )

        # Also check meta refresh in body
        if resp and resp.status_code == 200:
            body = resp.text or ''
            if 'safeweb-verify-redirect' in body and 'url=' in body.lower():
                return VerificationResult(
                    vuln_id=vuln_id, confirmed=True, confidence=0.8,
                    confirmation_method='secondary_payload',
                    evidence='Meta-refresh redirect detected with verification target',
                )

        return VerificationResult(
            vuln_id=vuln_id, confirmed=False, confidence=0.3,
            confirmation_method='secondary_payload',
            evidence='Redirect target not reflected in Location header',
        )

    # ── Generic Verification (Fallback) ──────────────────────────────────

    def _verify_generic(self, vuln: dict) -> VerificationResult:
        """Response diffing: compare payload request vs clean request."""
        vuln_id = vuln.get('_id', '')
        affected_url = vuln.get('affected_url', '')

        if not affected_url:
            return VerificationResult(
                vuln_id=vuln_id, confirmed=False, confidence=0.2,
                confirmation_method='response_diff',
                evidence='No affected URL available for verification',
            )

        # Clean baseline request
        resp_clean = self._safe_request('GET', affected_url)
        if not resp_clean:
            return VerificationResult(
                vuln_id=vuln_id, confirmed=False, confidence=0.2,
                confirmation_method='response_diff',
                evidence='Could not reach affected URL',
            )

        param = self._extract_param(vuln)
        if not param:
            # Re-request the exact URL — if it still shows anomalous behavior, confirm
            resp_replay = self._safe_request('GET', affected_url)
            if resp_replay:
                # Compare status codes
                if resp_replay.status_code >= 500:
                    return VerificationResult(
                        vuln_id=vuln_id, confirmed=True, confidence=0.6,
                        confirmation_method='behavioral',
                        evidence=f'Server error persists: HTTP {resp_replay.status_code}',
                    )
            return VerificationResult(
                vuln_id=vuln_id, confirmed=False, confidence=0.3,
                confirmation_method='response_diff',
                evidence='No injectable parameter found for diffing',
            )

        # Inject benign value
        benign_url = self._inject_param(affected_url, param, 'safeweb_benign_test')
        resp_benign = self._safe_request('GET', benign_url)

        # Inject trigger value
        trigger_url = self._inject_param(affected_url, param, "';--")
        resp_trigger = self._safe_request('GET', trigger_url)

        if resp_benign and resp_trigger:
            status_diff = resp_benign.status_code != resp_trigger.status_code
            len_benign = len(resp_benign.text or '')
            len_trigger = len(resp_trigger.text or '')
            len_diff = abs(len_trigger - len_benign)

            if status_diff or len_diff > 500:
                return VerificationResult(
                    vuln_id=vuln_id, confirmed=True, confidence=0.65,
                    confirmation_method='response_diff',
                    evidence=f'Behavioral difference: status {resp_benign.status_code}→{resp_trigger.status_code}, '
                             f'length delta={len_diff}',
                )

        return VerificationResult(
            vuln_id=vuln_id, confirmed=False, confidence=0.3,
            confirmation_method='response_diff',
            evidence='No significant response difference detected',
        )
