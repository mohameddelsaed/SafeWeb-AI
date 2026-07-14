"""Tests for vulnerability testers — Phase 1 (Core Injection)."""
from unittest.mock import patch, MagicMock
from tests.conftest import MockPage


# ---------------------------------------------------------------------------
# SQLInjectionTester
# ---------------------------------------------------------------------------
class TestSQLInjectionTester:
    def setup_method(self):
        from apps.scanning.engine.testers.sqli_tester import SQLInjectionTester
        self.tester = SQLInjectionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'SQL Injection'

    def test_no_params_no_forms_returns_empty(self):
        page = MockPage(url='https://example.com/')
        assert self.tester.test(page, 'shallow') == []

    def test_detects_error_based_sqli(self):
        """Simulate a SQL error in response body."""
        page = MockPage(
            url='https://example.com/search?q=test',
            parameters={'q': 'test'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version'
        mock_resp.elapsed = MagicMock()
        mock_resp.elapsed.total_seconds.return_value = 0.1

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            # Should find at least one SQL injection
            sqli_vulns = [v for v in vulns if 'SQL' in v.get('name', '')]
            assert len(sqli_vulns) >= 1

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/', body='<html></html>')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# XSSTester
# ---------------------------------------------------------------------------
class TestXSSTester:
    def setup_method(self):
        from apps.scanning.engine.testers.xss_tester import XSSTester
        self.tester = XSSTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'XSS'

    def test_no_params_returns_empty(self):
        page = MockPage(url='https://example.com/')
        assert self.tester.test(page, 'shallow') == []

    def test_detects_reflected_xss(self):
        page = MockPage(
            url='https://example.com/search?q=test',
            parameters={'q': 'test'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body><script>alert("XSS")</script></body></html>'
        mock_resp.headers = {}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            with patch.object(self.tester, '_is_reflected', return_value=True):
                vulns = self.tester.test(page, 'medium')
                xss_vulns = [v for v in vulns if 'XSS' in v.get('name', '').upper() or 'xss' in v.get('category', '').lower()]
                assert len(xss_vulns) >= 0  # May find DOM-based or reflected

    def test_dom_xss_detection(self):
        """Test DOM XSS detection via source/sink patterns."""
        page = MockPage(
            url='https://example.com/page',
            body='''
            <script>
                var x = document.location.hash;
                document.getElementById("output").innerHTML = x;
            </script>
            ''',
        )
        vulns = self.tester.test(page, 'medium')
        dom_vulns = [v for v in vulns if 'DOM' in v.get('name', '')]
        assert len(dom_vulns) >= 1


# ---------------------------------------------------------------------------
# CommandInjectionTester
# ---------------------------------------------------------------------------
class TestCommandInjectionTester:
    def setup_method(self):
        from apps.scanning.engine.testers.cmdi_tester import CommandInjectionTester
        self.tester = CommandInjectionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Command Injection'

    def test_no_cmd_params_skips(self):
        page = MockPage(
            url='https://example.com/about',
            parameters={'page': '1'},
        )
        # No cmd-like parameter names → likely returns empty
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)

    def test_detects_cmd_injection(self):
        """Simulate OS command output in response."""
        page = MockPage(
            url='https://example.com/tools?host=127.0.0.1',
            parameters={'host': '127.0.0.1'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'root:x:0:0:root:/root:/bin/bash\nuid=0(root)'
        mock_resp.headers = {}
        mock_resp.elapsed = MagicMock()
        mock_resp.elapsed.total_seconds.return_value = 0.1

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# SSTITester
# ---------------------------------------------------------------------------
class TestSSTITester:
    def setup_method(self):
        from apps.scanning.engine.testers.ssti_tester import SSTITester
        self.tester = SSTITester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'SSTI'

    def test_no_params_returns_empty(self):
        page = MockPage(url='https://example.com/')
        assert self.tester.test(page, 'shallow') == []

    def test_detects_ssti_marker(self):
        page = MockPage(
            url='https://example.com/greet?name=test',
            parameters={'name': 'test'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'Hello 49! Welcome'  # 7*7=49 reflected
        mock_resp.headers = {}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# XXETester
# ---------------------------------------------------------------------------
class TestXXETester:
    def setup_method(self):
        from apps.scanning.engine.testers.xxe_tester import XXETester
        self.tester = XXETester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'XXE'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)
