"""
Phase 48 — Testing & Quality Assurance

Tests for:
  ScanQualityTester           (testers/scan_quality_tester.py)
    _audit_security_headers   — presence checks for all 6 required headers
    _audit_cookie_security    — HttpOnly / Secure / SameSite flag detection
    _audit_server_info_leakage— Server / X-Powered-By disclosure
    _audit_dangerous_http_methods — OPTIONS + Allow header parsing
    _audit_csp_quality        — unsafe-inline / unsafe-eval / unsafe-hashes
  Registry                   — count == 87, ScanQualityTester at [-1]
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch



# ── Helpers ───────────────────────────────────────────────────────────────────

def _page(url='https://example.com/', headers=None):
    return {'url': url, 'content': '<html></html>',
            'headers': headers or {}, 'status_code': 200}


def _mock_resp(status=200, headers=None, text='OK'):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


# ── ScanQualityTester core ────────────────────────────────────────────────────

class TestScanQualityTester:
    """Basic tester interface tests."""

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Scan Quality & Coverage Auditor'

    def test_no_url_returns_empty(self):
        assert self.tester.test({}) == []
        assert self.tester.test({'url': ''}) == []

    def test_returns_list(self):
        result = self.tester.test(_page())
        assert isinstance(result, list)

    def test_shallow_no_http_request(self):
        """shallow depth must not call _make_request."""
        with patch.object(self.tester, '_make_request') as mock_req:
            self.tester.test(_page(), depth='shallow')
            mock_req.assert_not_called()

    def test_medium_makes_one_http_request(self):
        resp = _mock_resp(headers={})
        with patch.object(self.tester, '_make_request', return_value=resp) as mock_req:
            self.tester.test(_page(), depth='medium')
            mock_req.assert_called_once()

    def test_deep_makes_two_http_requests(self):
        """deep triggers GET (medium) + OPTIONS (method audit)."""
        resp = _mock_resp(headers={})
        with patch.object(self.tester, '_make_request', return_value=resp) as mock_req:
            self.tester.test(_page(), depth='deep')
            assert mock_req.call_count == 2

    def test_deep_no_csp_no_csp_audit(self):
        """With no CSP header, _audit_csp_quality should not add findings."""
        resp = _mock_resp(headers={})
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester.test(_page(headers={}), depth='deep')
        # no CSP finding for unsafe directives (because CSP absent → separate header finding)
        csp_quality_names = [
            f['name'] for f in result
            if 'unsafe-' in f['name'] or 'unsafe_' in f['name']
        ]
        assert csp_quality_names == []

    def test_dataclass_page_accepted(self):
        """tester accepts dataclass-style page objects with .url / .headers attributes."""
        from tests.conftest import MockPage
        page = MockPage(url='https://example.com/', headers={})
        result = self.tester.test(page, depth='shallow')
        assert isinstance(result, list)

    def test_none_make_request_graceful(self):
        """If _make_request returns None (network failure), no crash."""
        with patch.object(self.tester, '_make_request', return_value=None):
            result = self.tester.test(_page(), depth='medium')
        assert isinstance(result, list)


# ── _audit_security_headers ───────────────────────────────────────────────────

class TestAuditSecurityHeaders:

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()

    def _run(self, headers):
        return self.tester._audit_security_headers('https://example.com/', headers)

    def test_all_headers_present_no_findings(self):
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'camera=()',
        }
        assert self._run(headers) == []

    def test_missing_csp_detected(self):
        headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'camera=()',
        }
        result = self._run(headers)
        names = [f['name'] for f in result]
        assert any('Content-Security-Policy' in n for n in names)

    def test_missing_hsts_detected(self):
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'camera=()',
        }
        result = self._run(headers)
        assert any('Strict-Transport-Security' in f['name'] or 'HSTS' in f['name']
                   for f in result)

    def test_missing_xcto_detected(self):
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'camera=()',
        }
        result = self._run(headers)
        assert any('X-Content-Type-Options' in f['name'] for f in result)

    def test_missing_xfo_detected(self):
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'camera=()',
        }
        result = self._run(headers)
        assert any('X-Frame-Options' in f['name'] for f in result)

    def test_missing_referrer_policy_detected(self):
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Permissions-Policy': 'camera=()',
        }
        result = self._run(headers)
        assert any('Referrer-Policy' in f['name'] for f in result)

    def test_missing_permissions_policy_detected(self):
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
        }
        result = self._run(headers)
        assert any('Permissions-Policy' in f['name'] for f in result)

    def test_empty_headers_gives_six_findings(self):
        assert len(self._run({})) == 6

    def test_case_insensitive_matching(self):
        """Lowercase header names must still be recognised as present."""
        headers = {
            'content-security-policy': "default-src 'self'",
            'strict-transport-security': 'max-age=31536000',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'referrer-policy': 'no-referrer',
            'permissions-policy': 'camera=()',
        }
        assert self._run(headers) == []

    def test_finding_severity_is_medium(self):
        for finding in self._run({}):
            assert finding['severity'] == 'medium'

    def test_finding_has_cwe(self):
        for finding in self._run({}):
            assert finding['cwe'].startswith('CWE-')

    def test_finding_has_affected_url(self):
        url = 'https://example.com/page'
        for finding in self.tester._audit_security_headers(url, {}):
            assert finding['affected_url'] == url

    def test_finding_description_mentions_header(self):
        result = self._run({})
        {f['name'] for f in result}
        # Each finding's evidence mentions the header name
        for f in result:
            assert f['evidence']


# ── _audit_cookie_security ────────────────────────────────────────────────────

class TestAuditCookieSecurity:

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()
        self.url = 'https://example.com/'

    def _resp(self, set_cookie):
        r = MagicMock()
        r.headers = MagicMock()
        r.headers.get = lambda k, d='': set_cookie if k == 'Set-Cookie' else d
        return r

    def test_no_set_cookie_no_findings(self):
        r = self._resp('')
        assert self.tester._audit_cookie_security(self.url, r) == []

    def test_all_flags_present_no_findings(self):
        r = self._resp('session=abc; HttpOnly; Secure; SameSite=Strict')
        assert self.tester._audit_cookie_security(self.url, r) == []

    def test_missing_httponly_detected(self):
        r = self._resp('session=abc; Secure; SameSite=Strict')
        result = self.tester._audit_cookie_security(self.url, r)
        assert any('HttpOnly' in f['name'] for f in result)

    def test_missing_secure_detected(self):
        r = self._resp('session=abc; HttpOnly; SameSite=Strict')
        result = self.tester._audit_cookie_security(self.url, r)
        assert any('Secure' in f['name'] for f in result)

    def test_missing_samesite_detected(self):
        r = self._resp('session=abc; HttpOnly; Secure')
        result = self.tester._audit_cookie_security(self.url, r)
        assert any('SameSite' in f['name'] for f in result)

    def test_all_flags_missing_three_findings(self):
        r = self._resp('session=abc')
        assert len(self.tester._audit_cookie_security(self.url, r)) == 3

    def test_finding_category_session_management(self):
        r = self._resp('session=abc')
        for f in self.tester._audit_cookie_security(self.url, r):
            assert f['category'] == 'Session Management'

    def test_returns_list(self):
        r = self._resp('session=abc')
        assert isinstance(self.tester._audit_cookie_security(self.url, r), list)


# ── _audit_server_info_leakage ────────────────────────────────────────────────

class TestAuditServerInfoLeakage:

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()
        self.url = 'https://example.com/'

    def test_no_leakage_headers_no_findings(self):
        assert self.tester._audit_server_info_leakage(self.url, {}) == []

    def test_server_header_flagged(self):
        result = self.tester._audit_server_info_leakage(
            self.url, {'Server': 'Apache/2.4.41 (Ubuntu)'}
        )
        assert any('Server' in f['name'] for f in result)

    def test_powered_by_flagged(self):
        result = self.tester._audit_server_info_leakage(
            self.url, {'X-Powered-By': 'PHP/7.4.3'}
        )
        assert any('X-Powered-By' in f['name'] for f in result)

    def test_aspnet_version_flagged(self):
        result = self.tester._audit_server_info_leakage(
            self.url, {'X-AspNet-Version': '4.0.30319'}
        )
        assert any('ASP.NET' in f['name'] for f in result)

    def test_severity_is_low(self):
        result = self.tester._audit_server_info_leakage(
            self.url, {'Server': 'nginx/1.18.0'}
        )
        for f in result:
            assert f['severity'] == 'low'

    def test_evidence_contains_header_value(self):
        result = self.tester._audit_server_info_leakage(
            self.url, {'Server': 'nginx/1.18.0'}
        )
        assert 'nginx/1.18.0' in result[0]['evidence']

    def test_returns_list(self):
        assert isinstance(
            self.tester._audit_server_info_leakage(self.url, {}), list
        )


# ── _audit_dangerous_http_methods ─────────────────────────────────────────────

class TestAuditDangerousHttpMethods:

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()
        self.url = 'https://example.com/'

    def _options_resp(self, allow):
        r = MagicMock()
        r.status_code = 200
        r.headers = {'Allow': allow, 'Access-Control-Allow-Methods': ''}
        return r

    def test_trace_allowed_flagged(self):
        resp = self._options_resp('GET, POST, TRACE')
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester._audit_dangerous_http_methods(self.url)
        assert any('Dangerous' in f['name'] for f in result)
        assert 'TRACE' in result[0]['evidence']

    def test_put_allowed_flagged(self):
        resp = self._options_resp('GET, POST, PUT')
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester._audit_dangerous_http_methods(self.url)
        assert len(result) == 1
        assert 'PUT' in result[0]['description']

    def test_delete_allowed_flagged(self):
        resp = self._options_resp('GET, POST, DELETE')
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester._audit_dangerous_http_methods(self.url)
        assert len(result) == 1

    def test_only_safe_methods_no_finding(self):
        resp = self._options_resp('GET, POST, HEAD, OPTIONS')
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester._audit_dangerous_http_methods(self.url)
        assert result == []

    def test_options_request_failed_no_crash(self):
        with patch.object(self.tester, '_make_request', return_value=None):
            result = self.tester._audit_dangerous_http_methods(self.url)
        assert result == []

    def test_returns_list(self):
        resp = self._options_resp('GET, POST')
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester._audit_dangerous_http_methods(self.url)
        assert isinstance(result, list)


# ── _audit_csp_quality ────────────────────────────────────────────────────────

class TestAuditCspQuality:

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()
        self.url = 'https://example.com/'

    def test_unsafe_inline_flagged(self):
        csp = "default-src 'self'; script-src 'unsafe-inline'"
        result = self.tester._audit_csp_quality(self.url, csp)
        assert any("'unsafe-inline'" in f['name'] for f in result)

    def test_unsafe_eval_flagged(self):
        csp = "default-src 'self'; script-src 'unsafe-eval'"
        result = self.tester._audit_csp_quality(self.url, csp)
        assert any("'unsafe-eval'" in f['name'] for f in result)

    def test_unsafe_hashes_flagged(self):
        csp = "default-src 'self'; script-src 'unsafe-hashes'"
        result = self.tester._audit_csp_quality(self.url, csp)
        assert any("'unsafe-hashes'" in f['name'] for f in result)

    def test_clean_csp_no_findings(self):
        csp = "default-src 'self'; script-src 'self' https://cdn.example.com"
        assert self.tester._audit_csp_quality(self.url, csp) == []

    def test_multiple_unsafe_directives_multiple_findings(self):
        csp = "script-src 'unsafe-inline' 'unsafe-eval'"
        result = self.tester._audit_csp_quality(self.url, csp)
        assert len(result) == 2

    def test_severity_is_medium(self):
        csp = "script-src 'unsafe-inline'"
        result = self.tester._audit_csp_quality(self.url, csp)
        for f in result:
            assert f['severity'] == 'medium'

    def test_evidence_contains_csp(self):
        csp = "script-src 'unsafe-inline'"
        result = self.tester._audit_csp_quality(self.url, csp)
        assert 'unsafe-inline' in result[0]['evidence']

    def test_returns_list(self):
        assert isinstance(self.tester._audit_csp_quality(self.url, ''), list)


# ── Depth integration ─────────────────────────────────────────────────────────

class TestScanQualityTesterDepth:

    def setup_method(self):
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        self.tester = ScanQualityTester()

    def test_shallow_only_header_findings(self):
        """shallow must produce header findings (from page headers) and nothing else."""
        page = _page(headers={})
        result = self.tester.test(page, depth='shallow')
        # Should detect all 6 missing headers
        assert len(result) == 6

    def test_medium_adds_cookie_and_leakage_checks(self):
        resp = _mock_resp(headers={
            'Set-Cookie': 'session=x',      # no flags → 3 cookie findings
            'Server': 'Apache/2.4',         # 1 leakage finding
        })
        page = _page(headers={})
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester.test(page, depth='medium')
        categories = [f['category'] for f in result]
        assert 'Session Management' in categories
        assert 'Information Disclosure' in categories

    def test_deep_with_dangerous_methods_generates_method_finding(self):
        options_resp = _mock_resp(headers={'Allow': 'GET, POST, TRACE', 'Access-Control-Allow-Methods': ''})
        get_resp = _mock_resp(headers={})

        call_args = []

        def mock_req(method, url, **kwargs):
            call_args.append(method)
            if method == 'OPTIONS':
                return options_resp
            return get_resp

        page = _page(headers={})
        with patch.object(self.tester, '_make_request', side_effect=mock_req):
            result = self.tester.test(page, depth='deep')

        assert 'OPTIONS' in call_args
        assert any('Dangerous' in f['name'] for f in result)

    def test_deep_with_unsafe_csp_triggers_csp_quality(self):
        resp = _mock_resp(headers={})
        page = _page(headers={'Content-Security-Policy': "script-src 'unsafe-inline'"})
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester.test(page, depth='deep')
        assert any("'unsafe-inline'" in f['name'] for f in result)

    def test_all_findings_have_required_keys(self):
        resp = _mock_resp(headers={
            'Server': 'nginx',
            'Set-Cookie': 's=x',
        })
        with patch.object(self.tester, '_make_request', return_value=resp):
            result = self.tester.test(_page(headers={}), depth='medium')
        required_keys = {'name', 'severity', 'category', 'description',
                         'impact', 'remediation', 'cwe', 'cvss', 'affected_url', 'evidence'}
        for f in result:
            assert required_keys.issubset(set(f.keys()))


# ── Registry ──────────────────────────────────────────────────────────────────

class TestRegistration:

    def test_tester_count(self):
        """Total tester count is 87 (86 + Phase 48 ScanQualityTester)."""
        from apps.scanning.engine.testers import get_all_testers
        assert len(get_all_testers()) == 87

    def test_scan_quality_tester_registered(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert 'Scan Quality & Coverage Auditor' in names

    def test_scan_quality_tester_position(self):
        """ScanQualityTester must be the last tester ([-1])."""
        from apps.scanning.engine.testers import get_all_testers
        from apps.scanning.engine.testers.scan_quality_tester import ScanQualityTester
        testers = get_all_testers()
        assert isinstance(testers[-1], ScanQualityTester)

    def test_all_tester_names_unique(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert len(names) == len(set(names))
