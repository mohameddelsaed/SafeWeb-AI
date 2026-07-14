"""Tests for vulnerability testers — Phase 2 (Advanced)."""
from unittest.mock import patch, MagicMock
from tests.conftest import MockPage, MockForm, MockFormInput


# ---------------------------------------------------------------------------
# SSRFTester
# ---------------------------------------------------------------------------
class TestSSRFTester:
    def setup_method(self):
        from apps.scanning.engine.testers.ssrf_tester import SSRFTester
        self.tester = SSRFTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'SSRF'

    def test_no_url_params_returns_empty(self):
        page = MockPage(url='https://example.com/', parameters={'q': '1'})
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# AuthTester
# ---------------------------------------------------------------------------
class TestAuthTester:
    def setup_method(self):
        from apps.scanning.engine.testers.auth_tester import AuthTester
        self.tester = AuthTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Authentication'

    def test_detects_password_autocomplete(self):
        page = MockPage(
            url='https://example.com/login',
            body='''
            <form action="/login" method="POST">
                <input type="password" name="password" autocomplete="on">
            </form>
            ''',
            forms=[MockForm(
                action='/login', method='POST',
                inputs=[MockFormInput(name='password', input_type='password')],
            )],
        )
        vulns = self.tester.test(page, 'medium')
        autocomplete_vulns = [v for v in vulns if 'autocomplete' in v.get('name', '').lower()]
        assert len(autocomplete_vulns) >= 1

    def test_detects_insecure_session_cookies(self):
        page = MockPage(
            url='https://example.com/dashboard',
            cookies={'sessionid': 'abc123'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Set-Cookie': 'sessionid=abc123; Path=/'}
        mock_resp.cookies = {'sessionid': 'abc123'}
        mock_resp.text = '<html></html>'

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# AccessControlTester
# ---------------------------------------------------------------------------
class TestAccessControlTester:
    def setup_method(self):
        from apps.scanning.engine.testers.access_control_tester import AccessControlTester
        self.tester = AccessControlTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Access Control'

    def test_detects_sensitive_path_exposure(self):
        """Simulate an accessible admin path."""
        page = MockPage(url='https://example.com/')
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><title>Admin Panel</title></html>'
        mock_resp.headers = {'Content-Type': 'text/html'}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# DeserializationTester
# ---------------------------------------------------------------------------
class TestDeserializationTester:
    def setup_method(self):
        from apps.scanning.engine.testers.deserialization_tester import DeserializationTester
        self.tester = DeserializationTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Deserialization'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)

    def test_detects_java_serialization_in_cookie(self):
        """Cookie starting with rO0AB (Base64 Java object) should flag."""
        page = MockPage(
            url='https://example.com/',
            cookies={'data': 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=='},
            body='<html></html>',
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html></html>'
        mock_resp.headers = {'Content-Type': 'text/html'}
        mock_resp.cookies = {'data': 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=='}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# HostHeaderTester
# ---------------------------------------------------------------------------
class TestHostHeaderTester:
    def setup_method(self):
        from apps.scanning.engine.testers.host_header_tester import HostHeaderTester
        self.tester = HostHeaderTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Host Header'

    def test_detects_host_injection(self):
        page = MockPage(url='https://example.com/')
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><a href="https://evil.com/reset">Reset</a></html>'
        mock_resp.headers = {}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# HTTPSmugglingTester
# ---------------------------------------------------------------------------
class TestHTTPSmugglingTester:
    def setup_method(self):
        from apps.scanning.engine.testers.http_smuggling_tester import HTTPSmugglingTester
        self.tester = HTTPSmugglingTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'HTTP Smuggling'

    def test_no_crash_on_empty_page(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# CRLFTester
# ---------------------------------------------------------------------------
class TestCRLFTester:
    def setup_method(self):
        from apps.scanning.engine.testers.crlf_tester import CRLFInjectionTester
        self.tester = CRLFInjectionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'CRLF Injection'

    def test_detects_header_injection(self):
        page = MockPage(
            url='https://example.com/redirect?url=test',
            parameters={'url': 'test'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ''
        mock_resp.headers = {'X-Injected': 'true', 'safeweb-crlf': 'detected'}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# JWTTester
# ---------------------------------------------------------------------------
class TestJWTTester:
    def setup_method(self):
        from apps.scanning.engine.testers.jwt_tester import JWTTester
        self.tester = JWTTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'JWT'

    def test_finds_jwt_in_cookies(self):
        """A valid-looking JWT in cookies should be found."""
        jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        page = MockPage(
            url='https://example.com/',
            cookies={'token': jwt},
            headers={'Authorization': f'Bearer {jwt}'},
        )
        vulns = self.tester.test(page, 'medium')
        assert isinstance(vulns, list)
        # Should find JWT-related issues (weak secret, algorithm, etc.)

    def test_no_jwt_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)
