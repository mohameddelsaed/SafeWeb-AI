"""
Phase 28 — 403/401 Bypass Engine Tests.

Tests for:
  - ForbiddenBypassEngine (core engine: path, method, header, protocol, method-override)
  - ForbiddenBypassTester (BaseTester wrapper)
"""
from unittest.mock import patch, MagicMock

from tests.conftest import MockPage

from apps.scanning.engine.bypass.forbidden_bypass import (
    ForbiddenBypassEngine,
    PATH_MANIPULATIONS,
    BYPASS_METHODS,
    BYPASS_HEADERS,
    BLOCKED_STATUS_CODES,
    MIN_BYPASS_BODY_LENGTH,
)
from apps.scanning.engine.testers.forbidden_bypass_tester import ForbiddenBypassTester


# ═══════════════════════════════════════════════════════════════════════════════
# ForbiddenBypassEngine — unit tests
# ═══════════════════════════════════════════════════════════════════════════════
class TestForbiddenBypassEngine:

    def setup_method(self):
        self.engine = ForbiddenBypassEngine()

    # ── Constants sanity ─────────────────────────────────────────────────────

    def test_path_manipulations_exist(self):
        assert len(PATH_MANIPULATIONS) >= 20

    def test_bypass_methods_exist(self):
        assert 'POST' in BYPASS_METHODS
        assert 'PUT' in BYPASS_METHODS
        assert 'OPTIONS' in BYPASS_METHODS

    def test_bypass_headers_exist(self):
        assert len(BYPASS_HEADERS) >= 15

    def test_blocked_status_codes(self):
        assert 401 in BLOCKED_STATUS_CODES
        assert 403 in BLOCKED_STATUS_CODES

    # ── Engine.run basic behavior ────────────────────────────────────────────

    def test_returns_empty_on_non_blocked_status(self):
        results = self.engine.run('https://example.com/page', original_status_code=200)
        assert results == []

    def test_returns_empty_when_no_bypass_found(self):
        resp = MagicMock(status_code=403)
        resp.text = 'Forbidden'
        with patch.object(self.engine, '_make_request', return_value=resp):
            results = self.engine.run('https://example.com/admin', original_status_code=403)
        assert results == []

    # ── Path manipulation ────────────────────────────────────────────────────

    def test_path_manipulation_bypass(self):
        blocked = MagicMock(status_code=403)
        blocked.text = 'Forbidden'
        success = MagicMock(status_code=200)
        success.text = '<html>Admin Panel — you are logged in as admin.</html>' + 'A' * 50

        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            # First few attempts fail, then succeed on a path variation
            if '/' == url.rstrip('/')[-1:] or url.endswith('/.'):
                return success
            return blocked

        with patch.object(self.engine, '_make_request', side_effect=side_effect):
            results = self.engine.run(
                'https://example.com/admin',
                original_status_code=403,
                depth='shallow',
            )
        techs = [r['technique'] for r in results]
        assert 'path_manipulation' in techs

    def test_path_manipulation_variants_applied(self):
        """Verify path manipulations produce different URLs."""
        path = '/admin'
        seen = set()
        for manip in PATH_MANIPULATIONS:
            result = manip(path)
            seen.add(result)
        # Expect many unique variations
        assert len(seen) >= 15

    # ── HTTP method bypass ───────────────────────────────────────────────────

    def test_method_bypass(self):
        call_log = []

        def side_effect(method, url, **kwargs):
            call_log.append(method)
            if method == 'PUT':
                resp = MagicMock(status_code=200)
                resp.text = '<html>Admin dashboard content here with lots of data' + 'B' * 50 + '</html>'
                return resp
            resp = MagicMock(status_code=403)
            resp.text = 'Forbidden'
            return resp

        with patch.object(self.engine, '_make_request', side_effect=side_effect):
            results = self.engine.run(
                'https://example.com/admin',
                original_status_code=403,
                depth='medium',
            )
        method_results = [r for r in results if r['technique'] == 'method_bypass']
        assert len(method_results) >= 1
        assert method_results[0]['variant'] == 'PUT'

    # ── Header bypass ────────────────────────────────────────────────────────

    def test_header_bypass(self):
        blocked = MagicMock(status_code=403)
        blocked.text = 'Forbidden'

        def side_effect(method, url, **kwargs):
            headers = kwargs.get('headers', {})
            if 'X-Forwarded-For' in headers and headers['X-Forwarded-For'] == '127.0.0.1':
                resp = MagicMock(status_code=200)
                resp.text = '<html>Admin Panel — Welcome back, authorized user!</html>' + 'C' * 50
                return resp
            return blocked

        with patch.object(self.engine, '_make_request', side_effect=side_effect):
            results = self.engine.run(
                'https://example.com/admin',
                original_status_code=403,
                depth='medium',
            )
        header_results = [r for r in results if r['technique'] == 'header_bypass']
        assert len(header_results) >= 1
        assert '127.0.0.1' in header_results[0]['variant']

    def test_header_bypass_url_rewrite(self):
        blocked = MagicMock(status_code=403)
        blocked.text = 'Forbidden'

        def side_effect(method, url, **kwargs):
            headers = kwargs.get('headers', {})
            if 'X-Original-URL' in headers:
                resp = MagicMock(status_code=200)
                resp.text = '<html>Secret admin area content shown via X-Original-URL header</html>' + 'D' * 50
                return resp
            return blocked

        with patch.object(self.engine, '_make_request', side_effect=side_effect):
            results = self.engine.run(
                'https://example.com/admin',
                original_status_code=403,
                depth='medium',
            )
        header_results = [r for r in results if r['technique'] == 'header_bypass']
        assert len(header_results) >= 1
        assert 'X-Original-URL' in header_results[0]['variant']

    # ── Protocol bypass ──────────────────────────────────────────────────────

    def test_protocol_bypass_deep_only(self):
        blocked = MagicMock(status_code=403)
        blocked.text = 'Forbidden'

        def side_effect(method, url, **kwargs):
            headers = kwargs.get('headers', {})
            if headers.get('X-Forwarded-Proto') == 'https':
                resp = MagicMock(status_code=200)
                resp.text = '<html>SSL-only content revealed via protocol header manipulation</html>' + 'E' * 50
                return resp
            return blocked

        with patch.object(self.engine, '_make_request', side_effect=side_effect):
            results_shallow = self.engine.run(
                'https://example.com/admin',
                original_status_code=403,
                depth='shallow',
            )
            results_deep = self.engine.run(
                'https://example.com/admin',
                original_status_code=403,
                depth='deep',
            )
        proto_shallow = [r for r in results_shallow if r['technique'] == 'protocol_bypass']
        proto_deep = [r for r in results_deep if r['technique'] == 'protocol_bypass']
        assert len(proto_shallow) == 0
        assert len(proto_deep) >= 1

    # ── Method override ──────────────────────────────────────────────────────

    def test_method_override_bypass(self):
        blocked = MagicMock(status_code=403)
        blocked.text = 'Forbidden'

        def side_effect(method, url, **kwargs):
            headers = kwargs.get('headers', {})
            if method == 'POST' and headers.get('X-HTTP-Method-Override') == 'GET':
                resp = MagicMock(status_code=200)
                resp.text = '<html>Access granted via method override injection technique</html>' + 'F' * 50
                return resp
            return blocked

        with patch.object(self.engine, '_make_request', side_effect=side_effect):
            results = self.engine.run(
                'https://example.com/admin',
                original_status_code=403,
                depth='medium',
            )
        override_results = [r for r in results if r['technique'] == 'method_override']
        assert len(override_results) >= 1
        assert 'X-HTTP-Method-Override' in override_results[0]['variant']

    # ── _is_bypass ───────────────────────────────────────────────────────────

    def test_is_bypass_true_on_200(self):
        resp = MagicMock(status_code=200)
        resp.text = 'A' * (MIN_BYPASS_BODY_LENGTH + 1)
        assert self.engine._is_bypass(resp, 403) is True

    def test_is_bypass_false_on_same_status(self):
        resp = MagicMock(status_code=403)
        resp.text = 'A' * 200
        assert self.engine._is_bypass(resp, 403) is False

    def test_is_bypass_false_on_empty_body(self):
        resp = MagicMock(status_code=200)
        resp.text = ''
        assert self.engine._is_bypass(resp, 403) is False

    def test_is_bypass_false_on_none(self):
        assert self.engine._is_bypass(None, 403) is False

    def test_is_bypass_false_on_short_body(self):
        resp = MagicMock(status_code=200)
        resp.text = 'OK'
        assert self.engine._is_bypass(resp, 403) is False

    # ── _build_result ────────────────────────────────────────────────────────

    def test_build_result_structure(self):
        resp = MagicMock(status_code=200)
        resp.text = 'Hello ' * 20
        result = ForbiddenBypassEngine._build_result(
            technique='path_manipulation',
            variant='/admin/',
            resp=resp,
            url='https://example.com/admin/',
        )
        assert result['technique'] == 'path_manipulation'
        assert result['variant'] == '/admin/'
        assert result['status_code'] == 200
        assert result['body_length'] == len('Hello ' * 20)
        assert result['url'] == 'https://example.com/admin/'
        assert 'evidence' in result

    # ── Budget enforcement ───────────────────────────────────────────────────

    def test_respects_budget(self):
        call_count = [0]

        def side_effect(method, url, **kwargs):
            call_count[0] += 1
            resp = MagicMock(status_code=403)
            resp.text = 'Forbidden'
            return resp

        with patch.object(self.engine, '_make_request', side_effect=side_effect):
            self.engine.run(
                'https://example.com/admin',
                original_status_code=403,
                depth='shallow',
            )
        # shallow budget = 20
        assert call_count[0] <= 25  # small buffer for edge


# ═══════════════════════════════════════════════════════════════════════════════
# ForbiddenBypassTester — integration with BaseTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestForbiddenBypassTester:

    def setup_method(self):
        self.tester = ForbiddenBypassTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == '403/401 Bypass'

    def test_skips_200_status(self):
        page = MockPage(url='https://example.com/', status_code=200, body='OK')
        vulns = self.tester.test(page)
        assert vulns == []

    def test_skips_404_status(self):
        page = MockPage(url='https://example.com/nope', status_code=404, body='Not Found')
        vulns = self.tester.test(page)
        assert vulns == []

    def test_403_path_bypass_vuln_reported(self):
        page = MockPage(
            url='https://example.com/admin',
            status_code=403,
            body='Forbidden',
        )
        bypass_results = [{
            'technique': 'path_manipulation',
            'variant': '/admin/',
            'status_code': 200,
            'body_length': 300,
            'url': 'https://example.com/admin/',
            'evidence': 'path_manipulation: /admin/ → HTTP 200 (300 bytes)',
        }]
        with patch.object(self.tester._engine, 'run', return_value=bypass_results):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Path Manipulation Bypass' in names
        assert vulns[0]['severity'] == 'high'
        assert vulns[0]['category'] == 'Broken Access Control'

    def test_401_method_bypass_vuln_reported(self):
        page = MockPage(
            url='https://example.com/api/secret',
            status_code=401,
            body='Unauthorized',
        )
        bypass_results = [{
            'technique': 'method_bypass',
            'variant': 'PUT',
            'status_code': 200,
            'body_length': 500,
            'url': 'https://example.com/api/secret',
            'evidence': 'method_bypass: PUT → HTTP 200 (500 bytes)',
        }]
        with patch.object(self.tester._engine, 'run', return_value=bypass_results):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'HTTP Method Bypass' in names

    def test_header_bypass_critical(self):
        page = MockPage(
            url='https://example.com/admin',
            status_code=403,
            body='Forbidden',
        )
        bypass_results = [{
            'technique': 'header_bypass',
            'variant': 'X-Forwarded-For: 127.0.0.1',
            'status_code': 200,
            'body_length': 400,
            'url': 'https://example.com/admin',
            'evidence': 'header_bypass: X-Forwarded-For: 127.0.0.1 → HTTP 200',
        }]
        with patch.object(self.tester._engine, 'run', return_value=bypass_results):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Header-Based Access Control Bypass' in names
        assert vulns[0]['severity'] == 'critical'

    def test_method_override_bypass(self):
        page = MockPage(
            url='https://example.com/admin',
            status_code=403,
            body='Forbidden',
        )
        bypass_results = [{
            'technique': 'method_override',
            'variant': 'POST with X-HTTP-Method-Override: GET',
            'status_code': 200,
            'body_length': 600,
            'url': 'https://example.com/admin',
            'evidence': 'method_override: POST with X-HTTP-Method-Override: GET → HTTP 200',
        }]
        with patch.object(self.tester._engine, 'run', return_value=bypass_results):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Method Override Bypass' in names

    def test_protocol_bypass(self):
        page = MockPage(
            url='https://example.com/admin',
            status_code=403,
            body='Forbidden',
        )
        bypass_results = [{
            'technique': 'protocol_bypass',
            'variant': 'X-Forwarded-Proto: https',
            'status_code': 200,
            'body_length': 250,
            'url': 'https://example.com/admin',
            'evidence': 'protocol_bypass: X-Forwarded-Proto: https → HTTP 200',
        }]
        with patch.object(self.tester._engine, 'run', return_value=bypass_results):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Protocol Manipulation Bypass' in names
        assert vulns[0]['severity'] == 'medium'

    def test_multiple_techniques_grouped(self):
        page = MockPage(
            url='https://example.com/admin',
            status_code=403,
            body='Forbidden',
        )
        bypass_results = [
            {
                'technique': 'path_manipulation',
                'variant': '/admin/',
                'status_code': 200,
                'body_length': 300,
                'url': 'https://example.com/admin/',
                'evidence': 'path_manipulation: /admin/ → HTTP 200 (300 bytes)',
            },
            {
                'technique': 'path_manipulation',
                'variant': '/Admin',
                'status_code': 200,
                'body_length': 300,
                'url': 'https://example.com/Admin',
                'evidence': 'path_manipulation: /Admin → HTTP 200 (300 bytes)',
            },
            {
                'technique': 'header_bypass',
                'variant': 'X-Forwarded-For: 127.0.0.1',
                'status_code': 200,
                'body_length': 400,
                'url': 'https://example.com/admin',
                'evidence': 'header_bypass: X-Forwarded-For: 127.0.0.1 → HTTP 200',
            },
        ]
        with patch.object(self.tester._engine, 'run', return_value=bypass_results):
            vulns = self.tester.test(page)
        # Two techniques found → two vulns (path_manipulation grouped)
        assert len(vulns) == 2
        names = [v['name'] for v in vulns]
        assert 'Path Manipulation Bypass' in names
        assert 'Header-Based Access Control Bypass' in names

    def test_no_vuln_when_engine_returns_empty(self):
        page = MockPage(
            url='https://example.com/admin',
            status_code=403,
            body='Forbidden',
        )
        with patch.object(self.tester._engine, 'run', return_value=[]):
            vulns = self.tester.test(page)
        assert vulns == []

    def test_depth_passed_to_engine(self):
        page = MockPage(
            url='https://example.com/admin',
            status_code=403,
            body='Forbidden',
        )
        with patch.object(self.tester._engine, 'run', return_value=[]) as mock_run:
            self.tester.test(page, depth='deep')
        mock_run.assert_called_once_with(
            'https://example.com/admin',
            original_status_code=403,
            depth='deep',
        )
