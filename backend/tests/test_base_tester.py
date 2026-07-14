"""Tests for BaseTester common functionality."""
from unittest.mock import patch, MagicMock
from apps.scanning.engine.testers.base_tester import BaseTester


class ConcreteTester(BaseTester):
    """Concrete subclass for testing BaseTester mechanics."""
    TESTER_NAME = 'TestTester'

    def test(self, page, depth='medium'):
        return []


class TestBaseTesterInit:
    def test_session_created(self):
        tester = ConcreteTester()
        assert tester.session is not None
        assert 'SafeWeb' in tester.session.headers.get('User-Agent', '')

    def test_verify_disabled(self):
        tester = ConcreteTester()
        assert tester.session.verify is False

    def test_default_timeout(self):
        assert ConcreteTester.REQUEST_TIMEOUT == 10


class TestBuildVuln:
    def setup_method(self):
        self.tester = ConcreteTester()

    def test_basic_fields(self):
        vuln = self.tester._build_vuln(
            name='Test Vuln',
            severity='high',
            category='Injection',
            description='Test',
            impact='Test impact',
            remediation='Fix it',
            cwe='CWE-79',
            cvss=7.5,
            affected_url='https://example.com',
            evidence='Some evidence',
        )
        assert vuln['name'] == 'Test Vuln'
        assert vuln['severity'] == 'high'
        assert vuln['cvss'] == 7.5
        assert vuln['cwe'] == 'CWE-79'

    def test_auto_cvss_from_severity(self):
        """When cvss=0, it should auto-assign from SEVERITY_CVSS_MAP."""
        vuln = self.tester._build_vuln(
            name='Test', severity='critical', category='Test',
            description='', impact='', remediation='', cwe='',
            cvss=0, affected_url='', evidence='',
        )
        assert vuln['cvss'] == 9.5  # Default for critical

    def test_evidence_truncation(self):
        long_evidence = 'x' * 5000
        vuln = self.tester._build_vuln(
            name='Test', severity='low', category='Test',
            description='', impact='', remediation='', cwe='',
            cvss=3.0, affected_url='', evidence=long_evidence,
        )
        assert len(vuln['evidence']) == 2000


class TestMakeRequest:
    def setup_method(self):
        self.tester = ConcreteTester()

    @patch.object(ConcreteTester, '_make_request')
    def test_returns_response_on_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp
        resp = self.tester._make_request('GET', 'https://example.com')
        assert resp.status_code == 200

    def test_returns_none_on_timeout(self):
        with patch.object(self.tester.session, 'request', side_effect=Exception('Timeout')):
            resp = self.tester._make_request('GET', 'https://example.com')
            assert resp is None

    def test_returns_none_on_error(self):
        with patch.object(self.tester.session, 'request', side_effect=ConnectionError):
            resp = self.tester._make_request('GET', 'https://example.com')
            assert resp is None
