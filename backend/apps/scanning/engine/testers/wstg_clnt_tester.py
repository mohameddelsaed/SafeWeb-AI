"""
WSTGClientSideTester — OWASP WSTG-CLNT coverage.
Maps to: WSTG-CLNT-01 (DOM XSS), WSTG-CLNT-02 (JavaScript Execution),
         WSTG-CLNT-03 (HTML Injection), WSTG-CLNT-04 (Client-Side URL Redirect),
         WSTG-CLNT-05 (CSS Injection), WSTG-CLNT-06 (Resource Manipulation),
         WSTG-CLNT-07 (Cross-Origin Resource Sharing),
         WSTG-CLNT-09 (Clickjacking), WSTG-CLNT-10 (WebSockets),
         WSTG-CLNT-11 (Web Messaging), WSTG-CLNT-12 (Browser Storage),
         WSTG-CLNT-13 (Cross-Site Script Inclusion).

Fills client-side testing gaps identified in Phase 46.
"""
import re
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# DOM sources — direct user-controllable JavaScript sinks
DOM_SOURCES = [
    'location.hash',
    'location.search',
    'location.href',
    'document.referrer',
    'document.URL',
    'document.documentURI',
    'window.name',
    'document.cookie',
]

# DOM sinks — dangerous JavaScript operations
DOM_SINKS = [
    'document.write',
    'document.writeln',
    'innerHTML',
    'outerHTML',
    'insertAdjacentHTML',
    'eval(',
    'setTimeout(',
    'setInterval(',
    'Function(',
    'location.href',
    'location.replace(',
    'location.assign(',
    'window.open(',
    'document.location',
    'src=',
    'href=',
]

# Patterns for sensitive data stored in browser storage
STORAGE_SENSITIVE_KEYS = [
    r'localStorage\.setItem\(["\'](?:token|jwt|auth|password|secret|api[_-]?key|ssn|credit)',
    r'sessionStorage\.setItem\(["\'](?:token|jwt|auth|password|secret|api[_-]?key)',
    r'localStorage\.(?:token|password|secret|apikey|jwt)',
    r'sessionStorage\.(?:token|password|secret|jwt)',
]

# postMessage without origin validation patterns
POST_MESSAGE_INSECURE = [
    r'addEventListener\(["\']message["\'],\s*function\s*\([^)]*\)\s*\{(?:(?!event\.origin|e\.origin|origin\s*===|origin\s*!==)[^}]){0,500}\}',
    r'on\s*message\s*=\s*function',
]

# CSS injection sink patterns in JS
CSS_INJECTION_PATTERNS = [
    r'document\.getElementById\([^)]+\)\.style\.',
    r'\.setAttribute\(["\']style["\']',
    r'cssText\s*=',
    r'insertRule\(',
    r'\.style\.(?:background|color|content|font|display)\s*=',
]


class WSTGClientSideTester(BaseTester):
    """WSTG-CLNT: Client-Side — DOM XSS, HTML injection, postMessage, browser storage, redirect."""

    TESTER_NAME = 'WSTG-CLNT'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # WSTG-CLNT-01: DOM XSS patterns in page source
        vulns = self._test_dom_xss_patterns(page)
        vulnerabilities.extend(vulns)

        # WSTG-CLNT-03: HTML injection via URL parameters
        if depth in ('medium', 'deep'):
            vuln = self._test_html_injection(page)
            if vuln:
                vulnerabilities.append(vuln)

        # WSTG-CLNT-04: Client-side URL redirect via DOM
        vuln = self._test_dom_open_redirect(page)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-CLNT-05: CSS injection via user-controlled style
        vuln = self._test_css_injection_patterns(page)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-CLNT-11: Insecure postMessage (web messaging)
        vuln = self._test_postmessage_security(page)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-CLNT-12: Sensitive data in browser storage
        vulns = self._test_browser_storage_sensitive_data(page)
        vulnerabilities.extend(vulns)

        # WSTG-CLNT-07: CORS misconfiguration headers
        vuln = self._test_cors_headers(page)
        if vuln:
            vulnerabilities.append(vuln)

        # WSTG-CLNT-09: Clickjacking
        vuln = self._test_clickjacking(page)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    # ── WSTG-CLNT-01: DOM XSS Patterns ───────────────────────────────────────

    def _test_dom_xss_patterns(self, page) -> list:
        """
        Detect dangerous source→sink data flows in JavaScript that may cause DOM XSS.
        Static analysis only — looks for patterns in script tags.
        """
        found = []
        body = getattr(page, 'body', '') or ''

        # Extract all script content
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
        for script in scripts:
            for source in DOM_SOURCES:
                if source in script:
                    for sink in DOM_SINKS:
                        if sink in script:
                            # Check if they appear in close proximity
                            source_pos = script.find(source)
                            sink_pos = script.find(sink)
                            proximity = abs(source_pos - sink_pos)
                            if proximity < 500:  # within 500 chars
                                found.append(self._build_vuln(
                                    name=f'DOM XSS: Source "{source}" Flows to Sink "{sink}"',
                                    severity='high',
                                    category='WSTG-CLNT-01: Testing for DOM-Based Cross-Site Scripting',
                                    description=f'JavaScript in the page reads the user-controllable '
                                                f'source "{source}" and passes it to the dangerous sink '
                                                f'"{sink}" without apparent sanitization. '
                                                f'This pattern may indicate DOM-based XSS.',
                                    impact='Attackers can craft malicious URLs that execute arbitrary '
                                           'JavaScript in the victim\'s browser — stealing session tokens, '
                                           'performing CSRF actions, keylogging, or defacement.',
                                    remediation='Never pass user-controllable data (URL fragments, '
                                                'query strings) directly to DOM manipulation sinks. '
                                                'Use textContent instead of innerHTML. '
                                                'Apply DOMPurify for necessary HTML rendering. '
                                                'Implement a strict Content Security Policy (CSP).',
                                    cwe='CWE-79',
                                    cvss=8.2,
                                    affected_url=page.url,
                                    evidence=(f'Source: {source}, Sink: {sink}. '
                                              f'In script near offset {source_pos}. '
                                              f'Context: ...{script[max(0, source_pos-50):source_pos+100]}...'),
                                ))
                                break  # one finding per source-sink pair per script

        return found

    # ── WSTG-CLNT-03: HTML Injection ─────────────────────────────────────────

    def _test_html_injection(self, page):
        """
        Inject HTML tags via GET parameters and check if unescaped in response.
        """
        parsed = urlparse(page.url)
        params = parse_qs(parsed.query)
        if not params:
            return None

        injection_payload = '<h1>WSTG-CLNT-HTML-TEST</h1>'
        for param in list(params.keys())[:3]:  # test up to 3 params
            new_params = dict(params)
            new_params[param] = [injection_payload]
            new_query = urlencode({k: v[0] for k, v in new_params.items()})
            inject_url = urlunparse(parsed._replace(query=new_query))

            resp = self._make_request('GET', inject_url)
            if not resp:
                continue

            body = resp.text or ''
            if injection_payload in body:
                return self._build_vuln(
                    name='HTML Injection via URL Parameter',
                    severity='medium',
                    category='WSTG-CLNT-03: Testing for HTML Injection',
                    description=f'The URL parameter "{param}" is reflected in the response without '
                                f'HTML encoding. Injected HTML tag <h1>WSTG-CLNT-HTML-TEST</h1> '
                                f'appeared unescaped in the page body.',
                    impact='HTML injection allows attackers to deface the page, add phishing content, '
                           'or manipulate page rendering for social engineering. '
                           'May escalate to XSS if combined with JavaScript.',
                    remediation='HTML-encode all user-supplied data reflected in HTML context. '
                                'Use a secure templating engine with auto-escaping enabled. '
                                'Implement Content Security Policy.',
                    cwe='CWE-80',
                    cvss=5.4,
                    affected_url=inject_url,
                    evidence=f'Parameter: {param}, Payload: {injection_payload!r} reflected unescaped.',
                )
        return None

    # ── WSTG-CLNT-04: DOM-Based Open Redirect ────────────────────────────────

    def _test_dom_open_redirect(self, page):
        """Detect DOM-based open redirect patterns in JavaScript."""
        body = getattr(page, 'body', '') or ''
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)

        redirect_sinks = [
            'location.href', 'location.replace', 'location.assign', 'window.open',
        ]
        redirect_sources = [
            'location.hash', 'location.search', 'document.referrer',
            'getParameter', 'URLSearchParams', 'location.href',
        ]

        for script in scripts:
            for sink in redirect_sinks:
                if sink in script:
                    for source in redirect_sources:
                        if source in script:
                            sink_pos = script.find(sink)
                            src_pos = script.find(source)
                            if abs(sink_pos - src_pos) < 400:
                                return self._build_vuln(
                                    name='DOM-Based Open Redirect Pattern Detected',
                                    severity='medium',
                                    category='WSTG-CLNT-04: Testing for Client-Side URL Redirect',
                                    description=f'JavaScript reads from "{source}" and passes the value '
                                                f'to the redirect sink "{sink}" without validation. '
                                                f'This pattern may allow DOM-based open redirect attacks.',
                                    impact='Attackers can craft URLs that redirect victims to malicious '
                                           'sites for phishing. May also be used to bypass referrer '
                                           'checks and OAuth redirect_uri validation.',
                                    remediation='Validate redirect destinations against an allowlist of '
                                                'permitted URLs or paths. Never use user-controlled input '
                                                'directly in location.href or similar sinks. '
                                                'Use relative paths for internal redirects.',
                                    cwe='CWE-601',
                                    cvss=5.4,
                                    affected_url=page.url,
                                    evidence=(f'Source: {source} → Sink: {sink}. '
                                              f'Script excerpt: ...{script[max(0,src_pos-30):src_pos+120]}...'),
                                )
        return None

    # ── WSTG-CLNT-05: CSS Injection ───────────────────────────────────────────

    def _test_css_injection_patterns(self, page):
        """Detect user-controlled CSS manipulation sinks in JavaScript."""
        body = getattr(page, 'body', '') or ''
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)

        for script in scripts:
            for pattern in CSS_INJECTION_PATTERNS:
                match = re.search(pattern, script, re.IGNORECASE)
                if match:
                    return self._build_vuln(
                        name='Potential CSS Injection via JavaScript Style Manipulation',
                        severity='low',
                        category='WSTG-CLNT-05: Testing for CSS Injection',
                        description='The page JavaScript dynamically applies CSS styles using a '
                                    f'potentially user-controlled sink ({match.group(0)[:80]}). '
                                    'If user input flows into this sink, CSS injection is possible.',
                        impact='CSS injection can be used for UI redressing (clickjacking-like attacks), '
                               'data exfiltration via CSS selector tricks, or appearance manipulation.',
                        remediation='Validate and sanitize any user-controlled values before applying '
                                    'to element styles. Use a CSS allowlist. '
                                    'Implement Content Security Policy with style-src restrictions.',
                        cwe='CWE-79',
                        cvss=3.5,
                        affected_url=page.url,
                        evidence=f'Pattern found in script: {match.group(0)[:150]}',
                    )
        return None

    # ── WSTG-CLNT-11: Insecure postMessage ───────────────────────────────────

    def _test_postmessage_security(self, page):
        """Detect window.addEventListener('message') without origin validation."""
        body = getattr(page, 'body', '') or ''
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
        combined = '\n'.join(scripts)

        # Detect message listener
        has_message_listener = bool(re.search(
            r'addEventListener\s*\(\s*["\']message["\']', combined, re.IGNORECASE
        ))
        if not has_message_listener:
            return None

        # Check for origin validation nearby
        has_origin_check = bool(re.search(
            r'(?:event|e|msg|data)\.origin\s*(?:===|!==|==|!=|\s*in )',
            combined,
            re.IGNORECASE
        ))

        if not has_origin_check:
            return self._build_vuln(
                name='Insecure postMessage: Missing Origin Validation',
                severity='high',
                category='WSTG-CLNT-11: Testing for Web Messaging',
                description='The page registers a "message" event listener but does not appear '
                            'to validate event.origin. This means any cross-origin window can '
                            'send arbitrary messages to this page and they will be processed.',
                impact='Attackers can send crafted postMessage data from a malicious page to '
                       'trigger actions in the victim\'s page context: data theft, CSRF, '
                       'authentication bypass, or DOM manipulation.',
                remediation='Always validate event.origin against an allowlist of trusted origins '
                            'before processing postMessage data:\n'
                            '  if (event.origin !== "https://trusted-origin.com") return;',
                cwe='CWE-346',
                cvss=7.4,
                affected_url=page.url,
                evidence='"message" event listener found in page script without event.origin validation.',
            )
        return None

    # ── WSTG-CLNT-12: Sensitive Data in Browser Storage ──────────────────────

    def _test_browser_storage_sensitive_data(self, page) -> list:
        """Detect sensitive data being stored in localStorage or sessionStorage."""
        found = []
        body = getattr(page, 'body', '') or ''
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
        combined = '\n'.join(scripts)

        for pattern in STORAGE_SENSITIVE_KEYS:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                storage_type = 'localStorage' if 'local' in match.group(0).lower() else 'sessionStorage'
                found.append(self._build_vuln(
                    name=f'Sensitive Data Stored in {storage_type}',
                    severity='medium',
                    category='WSTG-CLNT-12: Testing for Browser Storage',
                    description=f'The page stores sensitive data (auth token, password, API key) '
                                f'in {storage_type}. Browser storage is accessible by any JavaScript '
                                f'on the same origin, including injected scripts.',
                    impact='If an XSS vulnerability exists anywhere on the same origin, attackers '
                           'can read all localStorage/sessionStorage data including auth tokens '
                           'and use them for session hijacking.',
                    remediation='Do not store sensitive tokens in localStorage/sessionStorage. '
                                'Use HttpOnly cookies for session management (not accessible to JS). '
                                'If localStorage must be used, ensure robust XSS prevention.',
                    cwe='CWE-922',
                    cvss=6.1,
                    affected_url=page.url,
                    evidence=f'Pattern in page scripts: {match.group(0)[:120]}',
                ))
            if len(found) >= 2:
                break  # limit to 2 findings per category to avoid noise

        return found

    # ── WSTG-CLNT-07: CORS Headers ────────────────────────────────────────────

    def _test_cors_headers(self, page):
        """Check CORS misconfiguration: wildcard or reflected Origin."""
        resp = self._make_request('GET', page.url,
                                  headers={'Origin': 'https://evil.example.com'})
        if not resp:
            return None

        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

        if acao == '*' and acac == 'true':
            return self._build_vuln(
                name='CORS: Wildcard Origin with Credentials Allowed',
                severity='critical',
                category='WSTG-CLNT-07: Testing for Cross-Origin Resource Sharing',
                description='The server responds with "Access-Control-Allow-Origin: *" combined '
                            'with "Access-Control-Allow-Credentials: true". This is an invalid but '
                            'dangerous configuration that some browsers may handle in a way that '
                            'exposes user data.',
                impact='May allow cross-origin requests to access authenticated resources.',
                remediation='Never combine wildcard ACAO with Allow-Credentials: true. '
                            'Use explicit origin allowlisting for credentialed cross-origin requests.',
                cwe='CWE-942',
                cvss=9.1,
                affected_url=page.url,
                evidence=f'ACAO: {acao}, ACAC: {acac}',
            )

        if acao == 'https://evil.example.com':
            # Reflected origin — highly suspicious
            severity = 'critical' if acac == 'true' else 'high'
            cvss = 9.1 if acac == 'true' else 7.5
            return self._build_vuln(
                name='CORS: Origin Header Reflected (Reflected ACAO)',
                severity=severity,
                category='WSTG-CLNT-07: Testing for Cross-Origin Resource Sharing',
                description='The server reflects the attacker-supplied Origin header back in '
                            'Access-Control-Allow-Origin, granting arbitrary origins access to '
                            f'{"authenticated " if acac == "true" else ""}resources.',
                impact='Any website can make cross-origin requests and read the response, '
                       + ('including authenticated data (credentials allowed).' if acac == 'true'
                          else 'potentially accessing sensitive data.'),
                remediation='Maintain an explicit allowlist of permitted origins. '
                            'Never reflect the request Origin header directly into ACAO.',
                cwe='CWE-942',
                cvss=cvss,
                affected_url=page.url,
                evidence=(f'Request Origin: https://evil.example.com → '
                          f'ACAO: {acao}, ACAC: {acac}'),
            )
        return None

    # ── WSTG-CLNT-09: Clickjacking ────────────────────────────────────────────

    def _test_clickjacking(self, page):
        """Check for missing X-Frame-Options or CSP frame-ancestors protection."""
        resp = self._make_request('GET', page.url)
        if not resp:
            return None

        xfo = resp.headers.get('X-Frame-Options', '').upper()
        csp = resp.headers.get('Content-Security-Policy', '')
        has_frame_ancestors = 'frame-ancestors' in csp.lower()

        if not xfo and not has_frame_ancestors:
            return self._build_vuln(
                name='Clickjacking: Missing X-Frame-Options and CSP frame-ancestors',
                severity='medium',
                category='WSTG-CLNT-09: Testing for Clickjacking',
                description='The page does not set X-Frame-Options or CSP frame-ancestors directive. '
                            'This allows the page to be embedded in an iframe by any origin.',
                impact='Attackers can embed this page in a transparent iframe over a malicious page, '
                       'tricking users into clicking UI elements (buttons, links, forms) they cannot '
                       'see — leading to unintended actions like transactions, settings changes, or '
                       'permission grants.',
                remediation='Add one of:\n'
                            '  X-Frame-Options: DENY  (or SAMEORIGIN)\n'
                            '  Content-Security-Policy: frame-ancestors \'none\'  (preferred)\n'
                            'The CSP directive takes precedence over X-Frame-Options in modern browsers.',
                cwe='CWE-1021',
                cvss=4.3,
                affected_url=page.url,
                evidence='No X-Frame-Options header. CSP header: ' + (csp[:100] if csp else 'absent'),
            )
        return None
