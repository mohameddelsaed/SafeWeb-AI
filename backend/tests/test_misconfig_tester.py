"""Tests for MisconfigTester (upgraded)."""
from unittest.mock import patch, MagicMock
from tests.conftest import MockPage


class TestMisconfigTester:
    def setup_method(self):
        from apps.scanning.engine.testers.misconfig_tester import MisconfigTester
        self.tester = MisconfigTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Misconfiguration'

    def test_detects_missing_security_headers(self):
        page = MockPage(
            url='https://example.com/',
            headers={'Content-Type': 'text/html'},
            body='<html><body>Hello</body></html>',
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>Hello</body></html>'
        mock_resp.headers = {'Content-Type': 'text/html'}  # Missing security headers

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            header_vulns = [v for v in vulns if 'header' in v.get('name', '').lower()]
            assert len(header_vulns) >= 1

    def test_detects_server_banner(self):
        page = MockPage(
            url='https://example.com/',
            headers={
                'Content-Type': 'text/html',
                'Server': 'Apache/2.4.41 (Ubuntu)',
            },
            body='<html></html>',
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html></html>'
        mock_resp.headers = {
            'Content-Type': 'text/html',
            'Server': 'Apache/2.4.41 (Ubuntu)',
        }

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            banner_vulns = [v for v in vulns if 'banner' in v.get('name', '').lower() or 'server' in v.get('name', '').lower()]
            assert len(banner_vulns) >= 1

    def test_detects_weak_csp(self):
        page = MockPage(
            url='https://example.com/',
            headers={
                'Content-Type': 'text/html',
                'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
            },
            body='<html></html>',
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html></html>'
        mock_resp.headers = {
            'Content-Type': 'text/html',
            'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
        }

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            csp_vulns = [v for v in vulns if 'content security policy' in v.get('name', '').lower() or 'csp' in v.get('name', '').lower()]
            assert len(csp_vulns) >= 1

    def test_detects_html_comments_with_secrets(self):
        page = MockPage(
            url='https://example.com/',
            headers={'Content-Type': 'text/html'},
            body='''
            <html>
            <!-- TODO: remove this API key: sk_live_abc123 -->
            <!-- password: admin123 -->
            <body>Hello</body>
            </html>
            ''',
        )
        vulns = self.tester.test(page, 'deep')
        comment_vulns = [v for v in vulns if 'comment' in v.get('name', '').lower()]
        assert len(comment_vulns) >= 1

    def test_detects_verbose_errors(self):
        page = MockPage(url='https://example.com/')
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = 'Traceback (most recent call last):\n  File "/app/views.py", line 42\nDjango Version: 5.0'
        mock_resp.headers = {}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            [v for v in vulns if 'error' in v.get('name', '').lower() or 'verbose' in v.get('name', '').lower()]
            assert isinstance(vulns, list)

    def test_no_issues_clean_headers(self):
        """A page with all security headers should have fewer findings."""
        page = MockPage(
            url='https://example.com/',
            headers={
                'Content-Type': 'text/html',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
                'Content-Security-Policy': "default-src 'self'",
                'X-XSS-Protection': '1; mode=block',
                'Referrer-Policy': 'strict-origin-when-cross-origin',
                'Permissions-Policy': 'geolocation=(self)',
            },
            body='<html></html>',
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html></html>'
        mock_resp.headers = dict(page.headers)

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
        header_vulns = [v for v in vulns if 'missing' in v.get('name', '').lower() and 'header' in v.get('name', '').lower()]
        assert len(header_vulns) == 0
