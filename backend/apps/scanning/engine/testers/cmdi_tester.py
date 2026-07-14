"""
CommandInjectionTester — OS Command Injection detection.
OWASP A03:2021 — Injection.

Tests for: bash/Windows command injection, blind time-based injection,
and filter bypass techniques across 70+ payloads.
"""
import re
import time
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester
from apps.scanning.engine.payloads.cmdi_payloads import (
    get_cmdi_payloads_by_depth,
    BLIND_PAYLOADS,
    COMMAND_OUTPUT_PATTERNS,
)

logger = logging.getLogger(__name__)

# Parameters likely to accept values passed to OS commands
CMD_PARAM_NAMES = [
    'cmd', 'command', 'exec', 'execute', 'run', 'ping', 'host',
    'hostname', 'ip', 'address', 'domain', 'target', 'query',
    'filename', 'file', 'filepath', 'path', 'dir', 'folder',
    'lookup', 'search', 'process', 'daemon', 'upload', 'download',
    'log', 'debug', 'test', 'include', 'param', 'option',
]

TIME_THRESHOLD = 4.0  # seconds — sleep 5 payload expected


class CommandInjectionTester(BaseTester):
    """Test for OS command injection vulnerabilities."""

    TESTER_NAME = 'Command Injection'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        payloads = get_cmdi_payloads_by_depth(depth)
        payloads = self._augment_payloads_with_seclists(payloads, 'command_injection', recon_data)

        # WAF-aware: use blind payloads first when WAF detected
        if self._should_use_waf_bypass(recon_data):
            payloads = BLIND_PAYLOADS + payloads
            logger.info('WAF detected — prepending blind CMDi payloads to evade signature-based WAF')

        # Test URL parameters
        for param_name in page.parameters:
            if not self._is_cmd_param(param_name):
                continue
            vuln = self._test_param_injection(page.url, param_name, payloads)
            if vuln:
                vulnerabilities.append(vuln)
                continue  # skip blind if already found

            # Blind time-based (medium/deep)
            if depth in ('medium', 'deep'):
                vuln = self._test_blind_injection(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

        # Test form inputs
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button', 'file'):
                    continue
                if not self._is_cmd_param(inp.name or ''):
                    continue
                vuln = self._test_form_injection(form, inp, payloads, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # OOB blind command injection — inject callbacks for blind RCE detection
        if depth in ('medium', 'deep'):
            self._inject_oob_cmdi(page, recon_data)

        return vulnerabilities

    def _inject_oob_cmdi(self, page, recon_data):
        """Inject OOB payloads for blind command injection detection."""
        for param_name in page.parameters:
            if not self._is_cmd_param(param_name):
                continue
            oob_payloads = self._get_oob_payloads('cmdi', param_name, page.url, recon_data)
            for payload, _callback_id in oob_payloads[:3]:
                self._make_request('GET', page.url, params={param_name: payload})
            break  # Limit to first cmd param

    # ------------------------------------------------------------------
    def _is_cmd_param(self, name: str) -> bool:
        return name.lower() in CMD_PARAM_NAMES

    # ------------------------------------------------------------------
    def _test_param_injection(self, url, param_name, payloads):
        """Inject command payloads via URL query parameter."""
        for payload in payloads:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))

            response = self._make_request('GET', test_url)
            if response and self._has_cmd_output(response.text):
                return self._build_vuln(
                    name=f'OS Command Injection: {param_name}',
                    severity='critical',
                    category='Command Injection',
                    description=f'The parameter "{param_name}" is vulnerable to OS command injection. '
                               f'Server-side command output was detected in the response.',
                    impact='An attacker can execute arbitrary system commands on the server, '
                          'leading to full system compromise, data exfiltration, or lateral movement.',
                    remediation='Never pass user input directly to OS commands. '
                               'Use parameterized APIs (e.g. subprocess with shell=False). '
                               'Apply strict input validation with allowlists.',
                    cwe='CWE-78',
                    cvss=9.8,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                            f'Command execution output detected in response.',
                )
        return None

    # ------------------------------------------------------------------
    def _test_blind_injection(self, url, param_name):
        """Time-based blind command injection."""
        for payload in BLIND_PAYLOADS[:4]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))

            start = time.time()
            response = self._make_request('GET', test_url, timeout=15)
            elapsed = time.time() - start

            if response and elapsed >= TIME_THRESHOLD:
                return self._build_vuln(
                    name=f'Blind Command Injection (Time-Based): {param_name}',
                    severity='critical',
                    category='Command Injection',
                    description=f'The parameter "{param_name}" is vulnerable to blind command injection. '
                               f'A time-delay payload caused a {elapsed:.1f}s response.',
                    impact='Even without visible output, attackers can exfiltrate data via DNS/HTTP '
                          'out-of-band channels, create reverse shells, or install backdoors.',
                    remediation='Same as command injection: avoid shell execution of user input. '
                               'Use safe APIs and strict allowlist validation.',
                    cwe='CWE-78',
                    cvss=9.8,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                            f'Response delayed {elapsed:.1f}s (threshold {TIME_THRESHOLD}s).',
                )
        return None

    # ------------------------------------------------------------------
    def _test_form_injection(self, form, inp, payloads, page_url):
        """Test form field for command injection."""
        for payload in payloads[:8]:
            data = {}
            for fi in form.inputs:
                if fi.name == inp.name:
                    data[fi.name] = payload
                else:
                    data[fi.name] = fi.value or 'test'

            target_url = form.action or page_url
            method = form.method.upper()
            if method == 'POST':
                response = self._make_request('POST', target_url, data=data)
            else:
                response = self._make_request('GET', target_url, params=data)

            if response and self._has_cmd_output(response.text):
                return self._build_vuln(
                    name=f'OS Command Injection in Form: {inp.name}',
                    severity='critical',
                    category='Command Injection',
                    description=f'The form field "{inp.name}" is vulnerable to OS command injection.',
                    impact='Full server compromise via arbitrary command execution.',
                    remediation='Never pass user input to shell commands. Use safe subprocess APIs.',
                    cwe='CWE-78',
                    cvss=9.8,
                    affected_url=target_url,
                    evidence=f'Field: {inp.name}\nPayload: {payload}',
                )
        return None

    # ------------------------------------------------------------------
    def _has_cmd_output(self, body: str) -> bool:
        """Check response for typical OS command output patterns."""
        if not body:
            return False
        for pattern in COMMAND_OUTPUT_PATTERNS:
            if re.search(pattern, body):
                return True
        return False
