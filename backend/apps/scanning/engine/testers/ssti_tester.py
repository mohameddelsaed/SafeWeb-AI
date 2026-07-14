"""
SSTITester — Server-Side Template Injection detection.
OWASP A03:2021 — Injection.

Detects template injection in Jinja2, Twig, Freemarker, Pebble, Mako,
Velocity, Smarty, ERB, and Handlebars engines.
"""
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester
from apps.scanning.engine.payloads.ssti_payloads import (
    get_ssti_payloads_by_depth,
    ENGINE_INDICATORS,
    JINJA2_PAYLOADS,
    TWIG_PAYLOADS,
    FREEMARKER_PAYLOADS,
    PEBBLE_PAYLOADS,
    MAKO_PAYLOADS,
    VELOCITY_PAYLOADS,
    SMARTY_PAYLOADS,
    ERB_PAYLOADS,
)

logger = logging.getLogger(__name__)

# Map engine name → exploitation payloads
ENGINE_EXPLOIT_MAP = {
    'Jinja2': JINJA2_PAYLOADS,
    'Twig': TWIG_PAYLOADS,
    'Freemarker': FREEMARKER_PAYLOADS,
    'Pebble': PEBBLE_PAYLOADS,
    'Mako': MAKO_PAYLOADS,
    'Velocity': VELOCITY_PAYLOADS,
    'Smarty': SMARTY_PAYLOADS,
    'ERB': ERB_PAYLOADS,
}

# Math-based detection markers
SSTI_MARKERS = {
    '{{7*7}}': '49',
    '${7*7}': '49',
    '#{7*7}': '49',
    '<%= 7*7 %>': '49',
    '{7*7}': '49',
    '{{7*\'7\'}}': '7777777',
    '${7*\'7\'}': '7777777',
}


class SSTITester(BaseTester):
    """Test for Server-Side Template Injection vulnerabilities."""

    TESTER_NAME = 'SSTI'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        payloads = get_ssti_payloads_by_depth(depth)
        payloads = self._augment_payloads_with_seclists(payloads, 'ssti', recon_data)

        # Tech-stack aware: prioritize engine-specific payloads when detected
        tech = self._get_tech_stack(recon_data)
        if tech:
            tech_lower = ' '.join(tech).lower() if isinstance(tech, list) else str(tech).lower()
            if 'jinja' in tech_lower or 'flask' in tech_lower:
                payloads = JINJA2_PAYLOADS + payloads
            elif 'twig' in tech_lower or 'symfony' in tech_lower:
                payloads = TWIG_PAYLOADS + payloads
            elif 'freemarker' in tech_lower or 'java' in tech_lower:
                payloads = FREEMARKER_PAYLOADS + payloads
            elif 'ruby' in tech_lower or 'rails' in tech_lower:
                payloads = ERB_PAYLOADS + payloads
            elif 'mako' in tech_lower:
                payloads = MAKO_PAYLOADS + payloads

        # Test URL parameters
        for param_name in page.parameters:
            vuln = self._test_ssti_param(page.url, param_name, payloads, depth)
            if vuln:
                vulnerabilities.append(vuln)

        # Test form inputs
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button', 'file'):
                    continue
                vuln = self._test_ssti_form(form, inp, payloads, page.url, depth)
                if vuln:
                    vulnerabilities.append(vuln)

        # OOB blind SSTI — inject callbacks for blind template injection detection
        if depth in ('medium', 'deep'):
            self._inject_oob_ssti(page, recon_data)

        return vulnerabilities

    def _inject_oob_ssti(self, page, recon_data):
        """Inject OOB payloads for blind SSTI detection."""
        for param_name in page.parameters:
            oob_payloads = self._get_oob_payloads('ssti', param_name, page.url, recon_data)
            for payload, _callback_id in oob_payloads[:2]:
                self._make_request('GET', page.url, params={param_name: payload})
            break  # Limit to first param

    # ------------------------------------------------------------------
    def _test_ssti_param(self, url, param_name, payloads, depth):
        """Test URL parameter for SSTI."""
        for payload in payloads:
            expected = SSTI_MARKERS.get(payload)
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))

            response = self._make_request('GET', test_url)
            if not response:
                continue

            body = response.text
            # Check for math evaluation
            if expected and expected in body and payload not in body:
                engine = self._identify_engine(url, param_name)
                return self._build_ssti_vuln(url, param_name, payload, engine)

            # Check for engine-specific indicators
            for engine, indicators in ENGINE_INDICATORS.items():
                for indicator in indicators:
                    if indicator in body and payload not in body:
                        return self._build_ssti_vuln(url, param_name, payload, engine)

        # Deep: try engine-specific exploitation payloads
        if depth == 'deep':
            for engine, exploit_payloads in ENGINE_EXPLOIT_MAP.items():
                for ep in exploit_payloads[:2]:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = ep
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(params, doseq=True), '',
                    ))
                    resp = self._make_request('GET', test_url)
                    if resp and self._has_ssti_evidence(resp.text, engine):
                        return self._build_ssti_vuln(url, param_name, ep, engine)

        return None

    # ------------------------------------------------------------------
    def _test_ssti_form(self, form, inp, payloads, page_url, depth):
        """Test form field for SSTI."""
        for payload in payloads:
            expected = SSTI_MARKERS.get(payload)
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

            if not response:
                continue

            body = response.text
            if expected and expected in body and payload not in body:
                engine = self._identify_engine_form(form, inp.name, page_url)
                return self._build_ssti_vuln(target_url, inp.name, payload, engine)

        return None

    # ------------------------------------------------------------------
    def _identify_engine(self, url, param_name):
        """Try to fingerprint the template engine."""
        fingerprints = [
            ("{{7*'7'}}", '7777777', 'Jinja2'),
            ("{{7*'7'}}", '49', 'Twig'),
            ('${7*7}', '49', 'Freemarker'),
            ('<%= 7*7 %>', '49', 'ERB'),
            ('{php}echo 7*7;{/php}', '49', 'Smarty'),
            ('#set($x=7*7)${x}', '49', 'Velocity'),
        ]
        parsed = urlparse(url)
        for payload, expected, engine in fingerprints:
            params = parse_qs(parsed.query)
            params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), '',
            ))
            resp = self._make_request('GET', test_url)
            if resp and expected in resp.text and payload not in resp.text:
                return engine
        return 'Unknown'

    def _identify_engine_form(self, form, inp_name, page_url):
        """Fingerprint template engine via form submission."""
        # Simplified: just return Unknown if we can't determine
        return 'Unknown'

    # ------------------------------------------------------------------
    def _has_ssti_evidence(self, body, engine):
        """Check for exploitation evidence based on engine."""
        if not body:
            return False
        evidence_patterns = [
            r'root:.*:0:0:',       # /etc/passwd read
            r'\buid=\d+',          # id command
            r'OS\s+Name',          # systeminfo
            r'__class__',          # Python MRO
            r'<class\s+\'',        # Python class repr
        ]
        for p in evidence_patterns:
            if re.search(p, body):
                return True
        return False

    # ------------------------------------------------------------------
    def _build_ssti_vuln(self, url, param_name, payload, engine):
        engine_label = engine if engine != 'Unknown' else 'an unidentified'
        severity = 'critical'
        cvss = 9.8

        return self._build_vuln(
            name=f'Server-Side Template Injection ({engine}): {param_name}',
            severity=severity,
            category='Template Injection',
            description=f'The parameter "{param_name}" is vulnerable to Server-Side Template Injection '
                       f'in {engine_label} template engine. User input is embedded directly into '
                       f'server-side template expressions without sanitization.',
            impact='An attacker can execute arbitrary code on the server, read files, '
                  'access internal services, and achieve full Remote Code Execution (RCE).',
            remediation='Never embed raw user input in template expressions. '
                       'Use sandboxed template environments. '
                       'Pass user data as template variables, not template code. '
                       'Consider using logic-less templates (Mustache/Handlebars).',
            cwe='CWE-1336',
            cvss=cvss,
            affected_url=url,
            evidence=f'Parameter: {param_name}\nPayload: {payload}\nEngine: {engine}',
        )
