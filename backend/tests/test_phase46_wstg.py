"""
Phase 46 — Full OWASP WSTG Coverage Tests.

Tests for all 10 WSTG testers:
  WSTGInfoTester         (WSTG-INFO)
  WSTGConfTester         (WSTG-CONF)
  WSTGIdentityTester     (WSTG-IDNT)
  WSTGAuthTester         (WSTG-ATHN)
  WSTGSessionTester      (WSTG-SESS)
  WSTGInputValidationTester  (WSTG-INPV)
  WSTGErrorHandlingTester    (WSTG-ERRH)
  WSTGCryptographyTester     (WSTG-CRYP)
  WSTGBusinessLogicTester    (WSTG-BUSL)
  WSTGClientSideTester       (WSTG-CLNT)
"""
from unittest.mock import patch, MagicMock

from tests.conftest import MockPage, MockForm, MockFormInput

from apps.scanning.engine.testers.wstg_info_tester import WSTGInfoTester
from apps.scanning.engine.testers.wstg_conf_tester import WSTGConfTester
from apps.scanning.engine.testers.wstg_idnt_tester import WSTGIdentityTester
from apps.scanning.engine.testers.wstg_athn_tester import WSTGAuthTester
from apps.scanning.engine.testers.wstg_sess_tester import WSTGSessionTester
from apps.scanning.engine.testers.wstg_inpv_tester import WSTGInputValidationTester
from apps.scanning.engine.testers.wstg_errh_tester import WSTGErrorHandlingTester
from apps.scanning.engine.testers.wstg_cryp_tester import WSTGCryptographyTester
from apps.scanning.engine.testers.wstg_busl_tester import WSTGBusinessLogicTester
from apps.scanning.engine.testers.wstg_clnt_tester import WSTGClientSideTester


# ─── Shared helpers ──────────────────────────────────────────────────────────

def make_resp(status=200, text='', headers=None, cookies=None, url='https://example.com/'):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.content = text.encode()
    resp.headers = headers or {}
    mock_cookies = MagicMock()
    mock_cookies.__iter__ = MagicMock(return_value=iter(cookies or []))
    resp.cookies = mock_cookies
    resp.url = url
    return resp


def make_cookie(name, value, **kwargs):
    c = MagicMock()
    c.name = name
    c.value = value
    for k, v in kwargs.items():
        setattr(c, k, v)
    return c


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGInfoTester  (WSTG-INFO)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGInfoTester:
    def setup_method(self):
        self.tester = WSTGInfoTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-INFO'

    def test_returns_list(self):
        page = MockPage(url='https://example.com/', body='<html></html>')
        with patch.object(self.tester, '_make_request', return_value=make_resp(404)):
            result = self.tester.test(page)
        assert isinstance(result, list)

    def test_metafiles_robots_found(self):
        page = MockPage(url='https://example.com/')
        robots_body = 'User-agent: *\nDisallow: /admin\nDisallow: /backup'
        resp_ok = make_resp(200, robots_body)
        with patch.object(self.tester, '_make_request', return_value=resp_ok):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert any('robots.txt' in n.lower() or 'metafile' in n.lower() or 'admin' in n.lower()
                   for n in names)

    def test_server_fingerprint_detected(self):
        page = MockPage(url='https://example.com/')
        page_resp = make_resp(200, '<html></html>',
                              headers={'Server': 'Apache/2.4.29 (Ubuntu)', 'X-Powered-By': 'PHP/7.2.0'})
        with patch.object(self.tester, '_make_request', return_value=page_resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert any('fingerprint' in n.lower() or 'banner' in n.lower() or 'server' in n.lower()
                   for n in names)

    def test_no_fingerprint_on_clean_headers(self):
        page = MockPage(url='https://example.com/')
        clean_resp = make_resp(200, '<html></html>',
                               headers={'Server': 'nginx', 'Content-Type': 'text/html'})
        with patch.object(self.tester, '_make_request', return_value=clean_resp):
            vulns = self.tester._test_server_fingerprint(page.url)
        assert vulns is None or (isinstance(vulns, list) and len(vulns) == 0) or vulns is None

    def test_entrypoints_hidden_sensitive_field(self):
        page = MockPage(
            url='https://example.com/profile',
            body='<form><input type="hidden" name="user_id" value="42"><input type="hidden" name="is_admin" value="false"></form>',
        )
        with patch.object(self.tester, '_make_request', return_value=make_resp(404)):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert any('admin' in n.lower() or 'entrypoint' in n.lower() or 'hidden' in n.lower()
                   for n in names)

    def test_robots_admin_disclosure(self):
        MockPage(url='https://example.com/')
        robots_resp = make_resp(200, 'User-agent: *\nDisallow: /admin\nDisallow: /api/internal')
        with patch.object(self.tester, '_make_request', return_value=robots_resp):
            vuln = self.tester._test_robots_disclosure('https://example.com/')
        assert vuln is not None
        assert 'robots' in vuln['name'].lower() or 'admin' in vuln['evidence'].lower()

    def test_robots_no_sensitive_paths(self):
        MockPage(url='https://example.com/')
        robots_resp = make_resp(200, 'User-agent: *\nDisallow: /images')
        with patch.object(self.tester, '_make_request', return_value=robots_resp):
            vuln = self.tester._test_robots_disclosure('https://example.com/')
        assert vuln is None


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGConfTester  (WSTG-CONF)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGConfTester:
    def setup_method(self):
        self.tester = WSTGConfTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-CONF'

    def test_backup_file_found(self):
        MockPage(url='https://example.com/index.php')
        backup_resp = make_resp(200, '<?php db_password = "secret"; ?>')
        not_found = make_resp(404, '')
        def side_effect(method, url, **kwargs):
            if '.bak' in url or '.backup' in url:
                return backup_resp
            return not_found
        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vulns = self.tester._test_backup_files('https://example.com/index.php')
        assert len(vulns) > 0
        assert 'backup' in vulns[0]['name'].lower() or 'bak' in vulns[0]['evidence'].lower()

    def test_backup_not_found(self):
        with patch.object(self.tester, '_make_request', return_value=make_resp(404)):
            vulns = self.tester._test_backup_files('https://example.com/index.php')
        assert vulns == []

    def test_http_trace_method(self):
        resp_trace = make_resp(200, 'TRACE / HTTP/1.1', headers={'Allow': 'GET, POST, TRACE, DELETE'})
        with patch.object(self.tester, '_make_request', return_value=resp_trace):
            vuln = self.tester._test_http_methods('https://example.com/')
        assert vuln is not None
        assert 'method' in vuln['name'].lower() or 'trace' in vuln['evidence'].lower()

    def test_ria_wildcard_crossdomain(self):
        xml_body = '<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>'
        with patch.object(self.tester, '_make_request', return_value=make_resp(200, xml_body)):
            vulns = self.tester._test_ria_cross_domain('https://example.com/')
        assert len(vulns) > 0
        assert 'cross-domain' in vulns[0]['name'].lower() or 'ria' in vulns[0]['name'].lower()

    def test_admin_interface_exposed(self):
        def side_effect(method, url, **kwargs):
            if '/admin' in url or '/phpmyadmin' in url:
                return make_resp(200, '<html><title>Admin Panel</title></html>')
            return make_resp(404)
        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vulns = self.tester._test_admin_interfaces('https://example.com/')
        assert len(vulns) > 0
        assert any('admin' in v['name'].lower() for v in vulns)

    def test_no_admin_interfaces(self):
        with patch.object(self.tester, '_make_request', return_value=make_resp(404)):
            vulns = self.tester._test_admin_interfaces('https://example.com/')
        assert vulns == []

    def test_returns_list(self):
        page = MockPage(url='https://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(404)):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGIdentityTester  (WSTG-IDNT)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGIdentityTester:
    def setup_method(self):
        self.tester = WSTGIdentityTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-IDNT'

    def test_account_enumeration_via_response_difference(self):
        page = MockPage(
            url='https://example.com/login',
            body='<html><form action="/login" method="POST"><input type="text" name="username"><input type="password" name="password"></form></html>',
            forms=[MockForm(action='/login', method='POST', inputs=[
                MockFormInput(name='username', input_type='text', value=''),
                MockFormInput(name='password', input_type='password', value=''),
            ])],
        )
        # Different response lengths for valid vs invalid
        real_resp = make_resp(200, 'A' * 500)
        fake_resp = make_resp(200, 'B' * 100)
        call_count = [0]
        def side_effect(method, url, **kw):
            call_count[0] += 1
            if call_count[0] % 2 == 0:
                return fake_resp
            return real_resp
        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert any('enumeration' in n.lower() for n in names)

    def test_role_exposure_in_html(self):
        page = MockPage(
            url='https://example.com/profile',
            body='<html><script>var userRole = "admin";</script></html>',
        )
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            vuln = self.tester._test_role_exposure(page)
        assert vuln is not None
        assert 'role' in vuln['name'].lower()

    def test_no_role_exposure(self):
        page = MockPage(url='https://example.com/', body='<html><p>Welcome</p></html>')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            vuln = self.tester._test_role_exposure(page)
        assert vuln is None

    def test_registration_no_captcha(self):
        page = MockPage(
            url='https://example.com/register',
            body='<form action="/register" method="POST"><input type="text" name="username"><input type="password" name="password"></form>',
            forms=[MockForm(action='/register', method='POST', inputs=[
                MockFormInput(name='username', input_type='text'),
                MockFormInput(name='password', input_type='password'),
            ])],
        )
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            vuln = self.tester._test_registration_process(page)
        assert vuln is not None
        assert 'captcha' in vuln['name'].lower() or 'registration' in vuln['name'].lower()

    def test_returns_list(self):
        page = MockPage(url='https://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGAuthTester  (WSTG-ATHN)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGAuthTester:
    def setup_method(self):
        self.tester = WSTGAuthTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-ATHN'

    def test_lockout_not_triggered(self):
        page = MockPage(
            url='https://example.com/login',
            body='<form action="/login" method="POST"><input type="text" name="username"><input type="password" name="password"></form>',
            forms=[MockForm(action='/login', method='POST', inputs=[
                MockFormInput(name='username', input_type='text'),
                MockFormInput(name='password', input_type='password'),
            ])],
        )
        # All responses 200 — no lockout
        with patch.object(self.tester, '_make_request', return_value=make_resp(200, 'Invalid password')):
            vuln = self.tester._test_lockout_mechanism(page)
        assert vuln is not None
        assert 'lockout' in vuln['name'].lower() or 'brute' in vuln['name'].lower()

    def test_lockout_triggered_no_vuln(self):
        page = MockPage(
            url='https://example.com/login',
            body='<form action="/login" method="POST"><input type="text" name="username"><input type="password" name="password"></form>',
            forms=[MockForm(action='/login', method='POST', inputs=[
                MockFormInput(name='username', input_type='text'),
                MockFormInput(name='password', input_type='password'),
            ])],
        )
        # After 3 requests, returns 429
        call_count = [0]
        def side_effect(*a, **kw):
            call_count[0] += 1
            if call_count[0] > 3:
                return make_resp(429, 'Too many requests')
            return make_resp(200, 'Invalid password')
        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vuln = self.tester._test_lockout_mechanism(page)
        assert vuln is None

    def test_browser_cache_no_header(self):
        resp = make_resp(200, '<html>Dashboard</html>', headers={})
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_browser_cache('https://example.com/dashboard')
        assert vuln is not None
        assert 'cache' in vuln['name'].lower()

    def test_browser_cache_proper_header(self):
        resp = make_resp(200, '<html>Dashboard</html>',
                         headers={'Cache-Control': 'no-store, no-cache, must-revalidate',
                                  'Pragma': 'no-cache'})
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_browser_cache('https://example.com/dashboard')
        assert vuln is None

    def test_captcha_absence_on_login(self):
        page = MockPage(
            url='https://example.com/login',
            body='<form action="/login" method="POST"><input type="text" name="username"><input type="password" name="password"><input type="submit"></form>',
            forms=[MockForm(action='/login', method='POST', inputs=[
                MockFormInput(name='username', input_type='text'),
                MockFormInput(name='password', input_type='password'),
            ])],
        )
        vuln = self.tester._test_captcha_absence(page)
        assert vuln is not None
        assert 'captcha' in vuln['name'].lower()

    def test_mfa_absent_on_login(self):
        page = MockPage(
            url='https://example.com/login',
            body='<form action="/login" method="POST"><input type="password" name="password"></form>',
        )
        vuln = self.tester._test_mfa_availability(page)
        assert vuln is not None
        assert any(kw in vuln['name'].lower() for kw in ('mfa', '2fa', 'multi-factor', 'authentication'))

    def test_returns_list(self):
        page = MockPage(url='https://example.com/login')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGSessionTester  (WSTG-SESS)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGSessionTester:
    def setup_method(self):
        self.tester = WSTGSessionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-SESS'

    def test_session_cookie_missing_flags(self):
        cookie = make_cookie('sessionid', 'abc123xyz456', has_flag=False)
        cookie.has_nonstandard_attr = MagicMock(return_value=False)
        cookie._rest = {}
        MockPage(url='https://example.com/')
        resp = make_resp(200, '')
        resp.cookies = [cookie]
        vuln = self.tester._test_session_schema(resp, 'https://example.com/')
        assert vuln is not None

    def test_session_predictability_low_entropy(self):
        # Method reads Set-Cookie header; set it directly
        resp = make_resp(200, '', headers={'Set-Cookie': 'sessionid=aaaaaaaaaa; Path=/'})
        vuln = self.tester._test_session_predictability(resp, 'https://example.com/')
        assert isinstance(vuln, list)
        assert len(vuln) > 0
        assert any('predict' in v['name'].lower() or 'entropy' in v['name'].lower() for v in vuln)

    def test_session_predictability_high_entropy(self):
        import secrets
        token = secrets.token_hex(32)  # high entropy random, 64 chars
        resp = make_resp(200, '', headers={'Set-Cookie': f'sessionid={token}; Path=/'})
        vulns = self.tester._test_session_predictability(resp, 'https://example.com/')
        assert isinstance(vulns, list)
        assert len(vulns) == 0

    def test_session_timeout_too_long(self):
        # Method reads Set-Cookie header; embed Max-Age directly
        resp = make_resp(200, '',
                         headers={'Set-Cookie': 'sessionid=abc123; Path=/; Max-Age=9999999'})
        vuln = self.tester._test_session_timeout('https://example.com/', resp)
        assert vuln is not None
        assert 'timeout' in vuln['name'].lower() or 'lifetime' in vuln['name'].lower()

    def test_logout_clears_session(self):
        logout_resp = make_resp(200, 'Logged out', headers={'Set-Cookie': 'sessionid=; Max-Age=0; Path=/'})
        page = MockPage(url='https://example.com/', body='<a href="/logout">Logout</a>')
        with patch.object(self.tester, '_make_request', return_value=logout_resp):
            vuln = self.tester._test_logout(page)
        assert vuln is None

    def test_returns_list(self):
        page = MockPage(url='https://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200, '', cookies=[])):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGInputValidationTester  (WSTG-INPV)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGInputValidationTester:
    def setup_method(self):
        self.tester = WSTGInputValidationTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-INPV'

    def test_verb_tampering_bypass(self):
        # 401 on GET, but 200 on HEAD
        restricted = make_resp(401, 'Unauthorized')
        bypass = make_resp(200, 'Secret content')
        def side_effect(method, url, **kw):
            if method == 'GET':
                return restricted
            return bypass
        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vuln = self.tester._test_verb_tampering('https://example.com/admin')
        assert vuln is not None
        assert 'verb' in vuln['name'].lower() or 'tamper' in vuln['name'].lower()

    def test_verb_tampering_all_restricted(self):
        with patch.object(self.tester, '_make_request', return_value=make_resp(403, 'Forbidden')):
            vuln = self.tester._test_verb_tampering('https://example.com/admin')
        assert vuln is None

    def test_expression_injection_detected(self):
        page = MockPage(
            url='https://example.com/search?q=test',
            body='<form action="/search" method="GET"><input type="text" name="q" value="test"></form>',
            forms=[MockForm(action='/search', method='GET', inputs=[
                MockFormInput(name='q', input_type='text', value='test'),
            ])],
            parameters={'q': 'test'},
        )
        # Response that contains "49" (7*7) when expression injected
        def side_effect(method, url, **kw):
            if '%247%2A7' in url or '%24%7B7%2A7%7D' in url or '${' in url or '49' in url:
                return make_resp(200, 'Result: 49 items found')
            return make_resp(200, 'Normal result')
        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vulns = self.tester._test_expression_injection(page)
        assert isinstance(vulns, list)
        assert len(vulns) > 0
        assert any('expression' in v['name'].lower() or 'injection' in v['name'].lower() for v in vulns)

    def test_header_injection_crlf(self):
        page = MockPage(
            url='https://example.com/redirect?url=test',
            body='',
            parameters={'url': 'test'},
        )
        injected_resp = make_resp(200, '', headers={'X-Injected': 'true'})
        with patch.object(self.tester, '_make_request', return_value=injected_resp):
            vulns = self.tester._test_header_injection(page)
        assert isinstance(vulns, list)
        assert len(vulns) > 0
        assert any('header' in v['name'].lower() or 'crlf' in v['name'].lower() for v in vulns)

    def test_returns_list(self):
        page = MockPage(url='https://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGErrorHandlingTester  (WSTG-ERRH)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGErrorHandlingTester:
    def setup_method(self):
        self.tester = WSTGErrorHandlingTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-ERRH'

    def test_stack_trace_detected(self):
        # Python traceback in 500 response
        traceback_body = '''
        Internal Server Error
        Traceback (most recent call last):
          File "/app/views.py", line 42, in get
            return SomeModel.objects.get(id=user_input)
        django.core.exceptions.ObjectDoesNotExist: No SomeModel matches the given query.
        '''
        resp = make_resp(500, traceback_body)
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_verbose_errors('https://example.com/')
        # _test_verbose_errors returns a single vuln dict or None
        assert vuln is not None
        assert 'stack' in vuln['name'].lower() or 'trace' in vuln['name'].lower() or 'error' in vuln['name'].lower()

    def test_no_stack_trace_on_clean(self):
        resp = make_resp(404, '<html><h1>Not Found</h1></html>')
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_verbose_errors('https://example.com/')
        assert vuln is None

    def test_debug_mode_detected(self):
        # Use body that contains a DEBUG_INDICATORS string
        debug_body = 'DEBUG = True\nsome other django debug toolbar content'
        resp = make_resp(200, debug_body)
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_debug_mode('https://example.com/')
        assert vuln is not None
        assert 'debug' in vuln['name'].lower()

    def test_path_disclosure_in_page(self):
        page = MockPage(
            url='https://example.com/',
            body='Error in /var/www/html/app/views.py at line 42',
        )
        vuln = self.tester._test_path_disclosure_in_page(page)
        assert vuln is not None
        assert 'path' in vuln['name'].lower() or 'disclosure' in vuln['name'].lower()

    def test_no_path_disclosure_clean(self):
        page = MockPage(url='https://example.com/', body='<html><p>Welcome!</p></html>')
        vuln = self.tester._test_path_disclosure_in_page(page)
        assert vuln is None

    def test_database_error_detected(self):
        sql_error_body = "SQLSTATE[42000]: Syntax error near 'WHERE' at line 1"
        resp = make_resp(500, sql_error_body)
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_database_errors('https://example.com/')
        assert vuln is not None
        assert 'database' in vuln['name'].lower() or 'sql' in vuln['name'].lower()

    def test_windows_path_in_page(self):
        page = MockPage(
            url='https://example.com/',
            body='Error at C:\\inetpub\\wwwroot\\WebApp\\Controllers\\HomeController.cs line 32',
        )
        vuln = self.tester._test_path_disclosure_in_page(page)
        assert vuln is not None

    def test_returns_list(self):
        page = MockPage(url='https://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGCryptographyTester  (WSTG-CRYP)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGCryptographyTester:
    def setup_method(self):
        self.tester = WSTGCryptographyTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-CRYP'

    def test_returns_list_for_http_page(self):
        page = MockPage(url='http://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            result = self.tester.test(page)
        assert isinstance(result, list)

    def test_unencrypted_password_form_http(self):
        page = MockPage(
            url='http://example.com/login',
            body='<form><input type="password" name="password"></form>',
            forms=[MockForm(action='http://example.com/login', method='POST', inputs=[
                MockFormInput(name='username', input_type='text'),
                MockFormInput(name='password', input_type='password'),
            ])],
        )
        vuln = self.tester._test_unencrypted_transmission(page)
        assert vuln is not None
        assert 'unencrypted' in vuln['name'].lower() or 'http' in vuln['name'].lower()

    def test_no_issue_on_https_page(self):
        page = MockPage(
            url='https://example.com/login',
            body='<form><input type="password" name="password"></form>',
            forms=[MockForm(action='https://example.com/login', method='POST', inputs=[
                MockFormInput(name='password', input_type='password'),
            ])],
        )
        vuln = self.tester._test_unencrypted_transmission(page)
        assert vuln is None

    def test_weak_hash_in_page_source(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>var hash = md5(userPassword);</script>',
        )
        vuln = self.tester._test_weak_crypto_in_source(page)
        assert vuln is not None
        assert 'weak' in vuln['name'].lower() or 'hash' in vuln['name'].lower()

    def test_no_weak_hash_clean_page(self):
        page = MockPage(url='https://example.com/', body='<html><p>Welcome</p></html>')
        vuln = self.tester._test_weak_crypto_in_source(page)
        assert vuln is None

    def test_exposed_secret_key(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>const SECRET_KEY = "supersecretkeyvalue123456789";</script>',
        )
        vulns = self.tester._test_exposed_crypto_material(page)
        assert len(vulns) > 0
        assert any('key' in v['name'].lower() or 'secret' in v['name'].lower() for v in vulns)

    def test_no_exposed_material_on_clean(self):
        page = MockPage(url='https://example.com/', body='<html><p>Clean page</p></html>')
        vulns = self.tester._test_exposed_crypto_material(page)
        assert vulns == []

    def test_returns_list_https(self):
        page = MockPage(url='https://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)), \
             patch('apps.scanning.engine.testers.wstg_cryp_tester.socket.create_connection',
                   side_effect=OSError('Connection refused')):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGBusinessLogicTester  (WSTG-BUSL)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGBusinessLogicTester:
    def setup_method(self):
        self.tester = WSTGBusinessLogicTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-BUSL'

    def test_price_parameter_tampering(self):
        page = MockPage(
            url='https://example.com/checkout',
            body='<form action="/checkout" method="POST"><input type="hidden" name="price" value="99.99"><input type="text" name="product"></form>',
            forms=[MockForm(action='https://example.com/checkout', method='POST', inputs=[
                MockFormInput(name='price', input_type='hidden', value='99.99'),
                MockFormInput(name='product', input_type='text', value='widget'),
            ])],
        )
        with patch.object(self.tester, '_make_request', return_value=make_resp(200, 'Order placed')):
            vulns = self.tester._test_parameter_tampering(page)
        assert len(vulns) > 0
        assert any('price' in v['name'].lower() or 'tamper' in v['name'].lower() for v in vulns)

    def test_quantity_negative_value_accepted(self):
        page = MockPage(
            url='https://example.com/cart',
            body='',
            forms=[MockForm(action='https://example.com/cart', method='POST', inputs=[
                MockFormInput(name='quantity', input_type='text', value='1'),
            ])],
        )
        with patch.object(self.tester, '_make_request', return_value=make_resp(200, 'Cart updated')):
            vulns = self.tester._test_negative_and_extreme_values(page)
        assert len(vulns) > 0

    def test_date_out_of_range_accepted(self):
        page = MockPage(
            url='https://example.com/booking',
            forms=[MockForm(action='https://example.com/booking', method='POST', inputs=[
                MockFormInput(name='date', input_type='date', value='2024-01-01'),
            ])],
        )
        with patch.object(self.tester, '_make_request', return_value=make_resp(200, 'Booking confirmed')):
            vulns = self.tester._test_date_manipulation(page)
        assert len(vulns) > 0

    def test_file_upload_no_accept(self):
        # Use MagicMock so that 'type' attribute (not 'input_type') returns 'file'
        file_input = MagicMock()
        file_input.type = 'file'
        file_input.name = 'file'
        file_input.accept = None
        page = MockPage(
            url='https://example.com/upload',
            forms=[MockForm(action='https://example.com/upload', method='POST',
                            inputs=[file_input])],
        )
        vuln = self.tester._test_file_upload_misuse(page)
        assert vuln is not None
        assert 'upload' in vuln['name'].lower() or 'file' in vuln['name'].lower()

    def test_workflow_bypass_step_skip(self):
        page = MockPage(url='https://example.com/checkout?step=2')
        with patch.object(self.tester, '_make_request',
                          return_value=make_resp(200, '<html>' + 'x' * 300 + '</html>')):
            vulns = self.tester._test_workflow_bypass(page)
        assert len(vulns) > 0
        assert any('workflow' in v['name'].lower() or 'step' in v['name'].lower() for v in vulns)

    def test_no_workflow_bypass_on_non_step_url(self):
        page = MockPage(url='https://example.com/about')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            vulns = self.tester._test_workflow_bypass(page)
        assert vulns == []

    def test_returns_list(self):
        page = MockPage(url='https://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WSTGClientSideTester  (WSTG-CLNT)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWSTGClientSideTester:
    def setup_method(self):
        self.tester = WSTGClientSideTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WSTG-CLNT'

    def test_dom_xss_source_to_sink(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>var u = location.hash; document.write(u);</script>',
        )
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            vulns = self.tester._test_dom_xss_patterns(page)
        assert len(vulns) > 0
        assert any('dom xss' in v['name'].lower() or 'xss' in v['name'].lower() for v in vulns)

    def test_no_dom_xss_safe_page(self):
        page = MockPage(url='https://example.com/', body='<p>Static content</p>')
        vulns = self.tester._test_dom_xss_patterns(page)
        assert vulns == []

    def test_html_injection_reflected(self):
        page = MockPage(url='https://example.com/search?q=test')
        # Response contains the injected h1 tag literally
        def side_effect(method, url, **kw):
            if 'WSTG-CLNT-HTML-TEST' in url:
                return make_resp(200, '<html><h1>WSTG-CLNT-HTML-TEST</h1></html>')
            return make_resp(200, '<html>Normal</html>')
        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vuln = self.tester._test_html_injection(page)
        assert vuln is not None
        assert 'html injection' in vuln['name'].lower()

    def test_no_html_injection_encoded(self):
        page = MockPage(url='https://example.com/search?q=test')
        # Response HTML-encodes the payload
        def side_effect(method, url, **kw):
            return make_resp(200, '<html>&lt;h1&gt;WSTG-CLNT-HTML-TEST&lt;/h1&gt;</html>')
        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vuln = self.tester._test_html_injection(page)
        assert vuln is None

    def test_dom_open_redirect_detected(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>var dest = location.search; window.open(dest);</script>',
        )
        vuln = self.tester._test_dom_open_redirect(page)
        assert vuln is not None
        assert 'redirect' in vuln['name'].lower()

    def test_no_dom_redirect_on_clean(self):
        page = MockPage(url='https://example.com/', body='<p>No JS</p>')
        vuln = self.tester._test_dom_open_redirect(page)
        assert vuln is None

    def test_postmessage_without_origin_check(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>window.addEventListener("message", function(evt) { doAction(evt.data); });</script>',
        )
        vuln = self.tester._test_postmessage_security(page)
        assert vuln is not None
        assert 'postmessage' in vuln['name'].lower() or 'origin' in vuln['name'].lower()

    def test_postmessage_with_origin_check_safe(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>window.addEventListener("message", function(e) { if (e.origin !== "https://trusted.com") return; doAction(e.data); });</script>',
        )
        vuln = self.tester._test_postmessage_security(page)
        assert vuln is None

    def test_browser_storage_sensitive_token(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>localStorage.setItem("token", userToken);</script>',
        )
        vulns = self.tester._test_browser_storage_sensitive_data(page)
        assert len(vulns) > 0
        assert any('storage' in v['name'].lower() for v in vulns)

    def test_no_sensitive_storage_clean(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>localStorage.setItem("theme", "dark");</script>',
        )
        vulns = self.tester._test_browser_storage_sensitive_data(page)
        assert vulns == []

    def test_cors_reflected_origin_with_credentials(self):
        page = MockPage(url='https://example.com/api/user')
        resp = make_resp(200, '', headers={
            'Access-Control-Allow-Origin': 'https://evil.example.com',
            'Access-Control-Allow-Credentials': 'true',
        })
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_cors_headers(page)
        assert vuln is not None
        assert 'cors' in vuln['name'].lower()
        assert vuln['severity'] == 'critical'

    def test_clickjacking_no_xfo(self):
        page = MockPage(url='https://example.com/')
        resp = make_resp(200, '<html></html>', headers={'Content-Type': 'text/html'})
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_clickjacking(page)
        assert vuln is not None
        assert 'clickjacking' in vuln['name'].lower()

    def test_clickjacking_with_xfo_deny(self):
        page = MockPage(url='https://example.com/')
        resp = make_resp(200, '<html></html>', headers={'X-Frame-Options': 'DENY'})
        with patch.object(self.tester, '_make_request', return_value=resp):
            vuln = self.tester._test_clickjacking(page)
        assert vuln is None

    def test_returns_list(self):
        page = MockPage(url='https://example.com/')
        with patch.object(self.tester, '_make_request', return_value=make_resp(200)):
            result = self.tester.test(page)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
# Registry tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase46Registry:
    """Ensure all 10 WSTG testers are registered in get_all_testers()."""

    def test_wstg_testers_in_registry(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        names = [getattr(t, 'TESTER_NAME', '') for t in testers]
        assert 'WSTG-INFO' in names
        assert 'WSTG-CONF' in names
        assert 'WSTG-IDNT' in names
        assert 'WSTG-ATHN' in names
        assert 'WSTG-SESS' in names
        assert 'WSTG-INPV' in names
        assert 'WSTG-ERRH' in names
        assert 'WSTG-CRYP' in names
        assert 'WSTG-BUSL' in names
        assert 'WSTG-CLNT' in names

    def test_total_tester_count_increased(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        # Phase 45 had 75 testers; Phase 46 adds 10 → expect ≥ 85
        assert len(testers) >= 85

    def test_all_testers_have_test_method(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        for tester in testers:
            assert callable(getattr(tester, 'test', None)), (
                f'{tester.__class__.__name__} is missing a test() method'
            )

    def test_wstg_tester_instantiation(self):
        """All 10 WSTG testers can be instantiated without error."""
        assert WSTGInfoTester()
        assert WSTGConfTester()
        assert WSTGIdentityTester()
        assert WSTGAuthTester()
        assert WSTGSessionTester()
        assert WSTGInputValidationTester()
        assert WSTGErrorHandlingTester()
        assert WSTGCryptographyTester()
        assert WSTGBusinessLogicTester()
        assert WSTGClientSideTester()
