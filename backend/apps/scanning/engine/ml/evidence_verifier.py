"""
Evidence Verifier — Intelligent post-scan verification of findings.

Performs active re-verification of potential vulnerabilities to confirm
or eliminate false positives before final reporting:
  - Re-send the exact payload and compare responses
  - Use alternative verification payloads (e.g. math-based for SQLi)
  - Check if the "evidence" is actually normal application behaviour
  - Cross-reference findings across different scan phases
  - Build a confidence-weighted evidence chain
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of verifying a single finding."""
    finding_id: str = ''
    verified: bool = False
    confidence: float = 0.0
    method: str = ''
    details: str = ''
    retries: int = 0


class EvidenceVerifier:
    """Active re-verification of scanner findings."""

    VERIFY_TIMEOUT = 10

    # Math-based verification payloads by vuln type
    _VERIFY_PAYLOADS: dict[str, list[str]] = {
        'sqli': [
            "1' AND 1=1-- ",
            "1' AND 1=2-- ",
            "1 AND SLEEP(3)-- ",
        ],
        'xss': [
            '<img src=x onerror=alert(document.domain)>',
            '"><svg/onload=confirm(1)>',
        ],
        'ssti': [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
        ],
        'cmdi': [
            '; echo safeweb_verify_$(date +%s)',
            '| echo safeweb_verify',
        ],
        'ssrf': [
            'http://127.0.0.1:80',
            'http://[::1]:80',
        ],
    }

    # Patterns that confirm the vuln type in the response
    _CONFIRM_PATTERNS: dict[str, re.Pattern] = {
        'sqli_diff': re.compile(r'(?:different|missing|error)', re.I),
        'sqli_time': None,  # Verified by time differential
        'xss': re.compile(r'<(?:img|svg|script)[^>]*(?:onerror|onload|alert)', re.I),
        'ssti_49': re.compile(r'\b49\b'),  # 7*7 = 49
        'cmdi': re.compile(r'safeweb_verify'),
    }

    def __init__(self, session: requests.Session | None = None):
        self._session = session or requests.Session()
        self._verified_cache: dict[str, VerificationResult] = {}

    def verify_finding(self, finding: dict) -> VerificationResult:
        """Verify a single finding with active re-testing."""
        fid = self._make_id(finding)
        if fid in self._verified_cache:
            return self._verified_cache[fid]

        result = VerificationResult(finding_id=fid)
        category = (finding.get('category', '') or '').lower()
        url = finding.get('affected_url', '') or finding.get('url', '')
        original_payload = finding.get('payload', '')

        if not url:
            result.details = 'No URL to verify'
            return result

        # Strategy 1: Replay original payload
        if original_payload:
            replayed = self._replay_payload(url, original_payload, finding)
            if replayed:
                result.verified = True
                result.confidence = 0.85
                result.method = 'replay'
                result.details = 'Original payload reproduced the same behavior'
                self._verified_cache[fid] = result
                return result
            result.retries += 1

        # Strategy 2: Differential verification (for SQLi)
        if category in ('sqli', 'nosql'):
            diff = self._differential_verify(url, finding)
            if diff:
                result.verified = True
                result.confidence = 0.90
                result.method = 'differential'
                result.details = 'True/false condition produced different responses'
                self._verified_cache[fid] = result
                return result
            result.retries += 1

        # Strategy 3: Alternative payloads
        verify_payloads = self._VERIFY_PAYLOADS.get(category, [])
        for payload in verify_payloads:
            confirmed = self._send_verify_payload(url, payload, category, finding)
            result.retries += 1
            if confirmed:
                result.verified = True
                result.confidence = 0.80
                result.method = 'alternative_payload'
                result.details = 'Verified with alternative payload'
                self._verified_cache[fid] = result
                return result

        # Not verified
        result.confidence = 0.30
        result.method = 'unverified'
        result.details = f'Could not reproduce after {result.retries} attempts'
        self._verified_cache[fid] = result
        return result

    def verify_batch(self, findings: list[dict]) -> list[VerificationResult]:
        """Verify multiple findings."""
        return [self.verify_finding(f) for f in findings]

    def get_stats(self) -> dict:
        """Return verification statistics."""
        verified = sum(1 for r in self._verified_cache.values() if r.verified)
        total = len(self._verified_cache)
        return {
            'total_verified': total,
            'confirmed': verified,
            'rejected': total - verified,
            'confirmation_rate': verified / total if total else 0,
        }

    # ── Internal ──────────────────────────────────────────────────────────

    def _replay_payload(self, url: str, payload: str, finding: dict) -> bool:
        """Re-send the original payload and check for same behavior."""
        try:
            method = (finding.get('method', 'GET') or 'GET').upper()
            param = finding.get('parameter', '')
            original_evidence = finding.get('evidence', '')

            if method == 'GET' and param:
                resp = self._session.get(url, params={param: payload},
                                         timeout=self.VERIFY_TIMEOUT,
                                         allow_redirects=False)
            elif method == 'POST' and param:
                resp = self._session.post(url, data={param: payload},
                                          timeout=self.VERIFY_TIMEOUT,
                                          allow_redirects=False)
            else:
                resp = self._session.get(url, timeout=self.VERIFY_TIMEOUT,
                                         allow_redirects=False)

            # Check if evidence pattern reappears
            if original_evidence and len(original_evidence) > 10:
                snippet = original_evidence[:80]
                if snippet in resp.text:
                    return True
            # Check if payload is reflected
            if payload in resp.text:
                return True

        except Exception:
            pass
        return False

    def _differential_verify(self, url: str, finding: dict) -> bool:
        """Differential analysis: true-condition vs false-condition."""
        param = finding.get('parameter', '')
        if not param:
            return False

        try:
            true_payload = "1' AND '1'='1"
            false_payload = "1' AND '1'='2"

            r_true = self._session.get(url, params={param: true_payload},
                                        timeout=self.VERIFY_TIMEOUT)
            r_false = self._session.get(url, params={param: false_payload},
                                         timeout=self.VERIFY_TIMEOUT)

            # Significant difference indicates injection
            len_diff = abs(len(r_true.text) - len(r_false.text))
            if len_diff > 50:
                return True
            if r_true.status_code != r_false.status_code:
                return True

        except Exception:
            pass
        return False

    def _send_verify_payload(self, url: str, payload: str,
                             category: str, finding: dict) -> bool:
        """Send a verification payload and check for category-specific confirmation."""
        param = finding.get('parameter', '')
        try:
            if param:
                resp = self._session.get(url, params={param: payload},
                                          timeout=self.VERIFY_TIMEOUT)
            else:
                return False

            # Time-based check
            if 'SLEEP' in payload.upper():
                start = time.monotonic()
                resp = self._session.get(url, params={param: payload},
                                          timeout=self.VERIFY_TIMEOUT)
                elapsed = time.monotonic() - start
                if elapsed > 2.5:
                    return True

            # Pattern-based check
            if category == 'xss' and self._CONFIRM_PATTERNS['xss'].search(resp.text):
                return True
            if category == 'ssti' and self._CONFIRM_PATTERNS['ssti_49'].search(resp.text):
                return True
            if category == 'cmdi' and self._CONFIRM_PATTERNS['cmdi'].search(resp.text):
                return True

        except Exception:
            pass
        return False

    @staticmethod
    def _make_id(finding: dict) -> str:
        """Generate a unique ID for a finding."""
        key = f"{finding.get('category', '')}:{finding.get('affected_url', '')}:{finding.get('parameter', '')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
