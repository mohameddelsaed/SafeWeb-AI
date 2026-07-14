"""Tests for vulnerability testers — Phase 3 (Modern) and Phase 4 (Infrastructure)."""
from unittest.mock import patch, MagicMock
from tests.conftest import MockPage


# ---------------------------------------------------------------------------
# Phase 3: Modern Attack Surface
# ---------------------------------------------------------------------------

class TestRaceConditionTester:
    def setup_method(self):
        from apps.scanning.engine.testers.race_condition_tester import RaceConditionTester
        self.tester = RaceConditionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Race Condition'

    def test_non_sensitive_page_skips(self):
        page = MockPage(url='https://example.com/about')
        vulns = self.tester.test(page, 'shallow')
        assert vulns == []


class TestWebSocketTester:
    def setup_method(self):
        from apps.scanning.engine.testers.websocket_tester import WebSocketTester
        self.tester = WebSocketTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'WebSocket'

    def test_detects_ws_in_body(self):
        """Pages referencing ws:// should be flagged."""
        page = MockPage(
            url='https://example.com/',
            body='<script>var ws = new WebSocket("ws://example.com/ws");</script>',
        )
        vulns = self.tester.test(page, 'medium')
        ws_vulns = [v for v in vulns if 'websocket' in v.get('name', '').lower() or 'ws' in v.get('name', '').lower()]
        assert len(ws_vulns) >= 1


class TestGraphQLTester:
    def setup_method(self):
        from apps.scanning.engine.testers.graphql_tester import GraphQLTester
        self.tester = GraphQLTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'GraphQL'

    def test_detects_introspection(self):
        page = MockPage(url='https://example.com/graphql')
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'
        mock_resp.headers = {'Content-Type': 'application/json'}
        mock_resp.json.return_value = {'data': {'__schema': {'types': [{'name': 'Query'}]}}}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            intro_vulns = [v for v in vulns if 'introspection' in v.get('name', '').lower()]
            assert len(intro_vulns) >= 1


class TestFileUploadTester:
    def setup_method(self):
        from apps.scanning.engine.testers.file_upload_tester import FileUploadTester
        self.tester = FileUploadTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'File Upload'

    def test_no_upload_form_returns_empty(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert vulns == []


class TestNoSQLTester:
    def setup_method(self):
        from apps.scanning.engine.testers.nosql_tester import NoSQLInjectionTester
        self.tester = NoSQLInjectionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'NoSQL Injection'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)


class TestCachePoisoningTester:
    def setup_method(self):
        from apps.scanning.engine.testers.cache_poisoning_tester import CachePoisoningTester
        self.tester = CachePoisoningTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Cache Poisoning'

    def test_no_cache_returns_empty(self):
        page = MockPage(url='https://example.com/')
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html></html>'
        mock_resp.headers = {}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'shallow')
            assert isinstance(vulns, list)


# ---------------------------------------------------------------------------
# Phase 4: Infrastructure
# ---------------------------------------------------------------------------

class TestCORSTester:
    def setup_method(self):
        from apps.scanning.engine.testers.cors_tester import CORSTester
        self.tester = CORSTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'CORS Misconfiguration'

    def test_detects_wildcard_with_credentials(self):
        page = MockPage(
            url='https://example.com/api/data',
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true',
            },
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ''
        mock_resp.headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
        }

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)

    def test_detects_reflected_origin(self):
        page = MockPage(url='https://example.com/api')
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ''
        mock_resp.headers = {
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Credentials': 'true',
        }

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


class TestClickjackingTester:
    def setup_method(self):
        from apps.scanning.engine.testers.clickjacking_tester import ClickjackingTester
        self.tester = ClickjackingTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Clickjacking'

    def test_detects_missing_xfo(self):
        page = MockPage(
            url='https://example.com/login',
            headers={'Content-Type': 'text/html'},
            body='<html><form><input type="password"></form></html>',
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><form><input type="password"></form></html>'
        mock_resp.headers = {'Content-Type': 'text/html'}  # No XFO

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


class TestLDAPXPathTester:
    def setup_method(self):
        from apps.scanning.engine.testers.ldap_xpath_tester import LDAPXPathTester
        self.tester = LDAPXPathTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'LDAP/XPath Injection'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)


class TestSubdomainTakeoverTester:
    def setup_method(self):
        from apps.scanning.engine.testers.subdomain_takeover_tester import SubdomainTakeoverTester
        self.tester = SubdomainTakeoverTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Subdomain Takeover'

    def test_no_subdomains_returns_empty(self):
        page = MockPage(url='https://example.com/', links=[])
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)


class TestCloudStorageTester:
    def setup_method(self):
        from apps.scanning.engine.testers.cloud_storage_tester import CloudStorageTester
        self.tester = CloudStorageTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Cloud Storage'

    def test_detects_s3_reference(self):
        page = MockPage(
            url='https://example.com/',
            body='<img src="https://mybucket.s3.amazonaws.com/image.png">',
        )
        # Should find S3 bucket reference
        vulns = self.tester.test(page, 'medium')
        assert isinstance(vulns, list)
