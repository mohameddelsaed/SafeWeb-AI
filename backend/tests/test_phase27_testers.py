"""
Phase 27 — New Vulnerability Classes (Batch 2) Tests.

Tests for: WebCacheDeceptionTester, XSLeakTester, XSLTInjectionTester,
ZipSlipTester, VHostTester, InsecureRandomnessTester,
ReverseProxyMisconfigTester, DependencyConfusionTester.
"""
from unittest.mock import patch, MagicMock

from tests.conftest import MockPage, MockForm, MockFormInput

from apps.scanning.engine.testers.web_cache_deception_tester import WebCacheDeceptionTester
from apps.scanning.engine.testers.xsleak_tester import XSLeakTester
from apps.scanning.engine.testers.xslt_injection_tester import XSLTInjectionTester
from apps.scanning.engine.testers.zip_slip_tester import ZipSlipTester
from apps.scanning.engine.testers.vhost_tester import VHostTester
from apps.scanning.engine.testers.insecure_randomness_tester import InsecureRandomnessTester
from apps.scanning.engine.testers.reverse_proxy_misconfig_tester import ReverseProxyMisconfigTester
from apps.scanning.engine.testers.dependency_confusion_tester import DependencyConfusionTester


# ═══════════════════════════════════════════════════════════════════════════════
# WebCacheDeceptionTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestWebCacheDeceptionTester:
    def setup_method(self):
        self.tester = WebCacheDeceptionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Web Cache Deception'

    def test_path_confusion_with_sensitive_data(self):
        page = MockPage(
            url='https://example.com/account/profile',
            body='<html>Your email: user@example.com, api_key="sk-abc123def456"</html>',
        )
        resp = MagicMock(status_code=200)
        resp.text = 'Your email: user@example.com, api_key="sk-abc123def456"'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Web Cache Deception' in names

    def test_unkeyed_header_poisoning(self):
        page = MockPage(
            url='https://example.com/page',
            body='<html>Normal</html>',
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>Redirect to evil.example.com</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Cache Poisoning via Unkeyed Header' in names

    def test_cache_key_normalization(self):
        page = MockPage(
            url='https://example.com/page/data',
            body='<html>Content here with enough text to exceed the threshold</html>',
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>Content here with enough text to exceed the threshold plus extra padding for length</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Cache Key Normalization Issue' in names

    def test_no_vuln_on_non_sensitive_url(self):
        page = MockPage(
            url='https://example.com/about',
            body='<html>About us</html>',
        )
        resp = MagicMock(status_code=404)
        resp.text = 'Not Found'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='shallow')
        assert vulns == []

    def test_no_vuln_on_clean_page(self):
        page = MockPage(
            url='https://example.com/',
            body='<html>Home</html>',
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>Home</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        # No sensitive URL, so no path confusion test; unkeyed header returns
        # no reflected value, so no cache poisoning
        cache_vulns = [v for v in vulns if 'Cache' in v['name'] or 'Deception' in v['name']]
        assert len(cache_vulns) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# XSLeakTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestXSLeakTester:
    def setup_method(self):
        self.tester = XSLeakTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'XS-Leak'

    def test_missing_mitigation_headers(self):
        page = MockPage(
            url='https://example.com/api/user/profile',
            body='<html>User data</html>',
            headers={},
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Missing XS-Leak Mitigations' in names

    def test_no_vuln_with_all_headers(self):
        page = MockPage(
            url='https://example.com/api/user/profile',
            body='<html>User data</html>',
            headers={
                'Cross-Origin-Opener-Policy': 'same-origin',
                'Cross-Origin-Resource-Policy': 'same-origin',
                'Cross-Origin-Embedder-Policy': 'require-corp',
                'X-Frame-Options': 'DENY',
            },
        )
        vulns = self.tester.test(page, depth='shallow')
        names = [v['name'] for v in vulns]
        assert 'Missing XS-Leak Mitigations' not in names

    def test_error_based_leak(self):
        page = MockPage(
            url='https://example.com/api/data',
            body='<html>Data</html>',
            headers={
                'Cross-Origin-Opener-Policy': 'same-origin',
                'Cross-Origin-Resource-Policy': 'same-origin',
                'Cross-Origin-Embedder-Policy': 'require-corp',
                'X-Frame-Options': 'DENY',
            },
        )
        resp = MagicMock(status_code=403)
        resp.text = 'Traceback (most recent call last): File "app.py" exception debug'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Error-Based XS-Leak Vector' in names

    def test_navigation_leak(self):
        page = MockPage(
            url='https://example.com/account/settings',
            body='<html>Settings</html>',
            headers={},
        )
        # 1st call: error-based leak probe, 2nd+3rd: navigation leak
        resp_error = MagicMock(status_code=404)
        resp_error.text = 'Not Found'
        resp_error.headers = {}
        resp_normal = MagicMock(status_code=302)
        resp_normal.text = ''
        resp_normal.headers = {'Location': '/dashboard'}
        resp_no_cookie = MagicMock(status_code=302)
        resp_no_cookie.text = ''
        resp_no_cookie.headers = {'Location': '/login'}
        with patch.object(
            self.tester, '_make_request',
            side_effect=[resp_error, resp_normal, resp_no_cookie],
        ):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Navigation-Based XS-Leak' in names

    def test_no_vuln_on_non_sensitive_url(self):
        page = MockPage(
            url='https://example.com/robots.txt',
            body='User-agent: *',
            headers={},
        )
        vulns = self.tester.test(page, depth='shallow')
        assert vulns == []


# ═══════════════════════════════════════════════════════════════════════════════
# XSLTInjectionTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestXSLTInjectionTester:
    def setup_method(self):
        self.tester = XSLTInjectionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'XSLT Injection'

    def test_xslt_indicators_in_body(self):
        page = MockPage(
            url='https://example.com/report',
            body='<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"></xsl:template></xsl:stylesheet>',
            headers={'Content-Type': 'text/xml'},
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'XSLT Processing Detected' in names

    def test_param_xslt_injection(self):
        page = MockPage(
            url='https://example.com/transform?xml=data',
            body='<result>Output</result>',
            parameters={'xml': 'data'},
            headers={'Content-Type': 'text/xml'},
        )
        resp = MagicMock(status_code=200)
        resp.text = 'XSLT version: 1.0 processed by libxslt'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'XSLT Injection via Parameter' in names

    def test_form_xslt_injection(self):
        page = MockPage(
            url='https://example.com/render',
            body='<form><input name="xml"></form>',
            forms=[MockForm(
                action='/render', method='POST',
                inputs=[MockFormInput(name='xml', input_type='text')],
            )],
            headers={'Content-Type': 'text/xml'},
        )
        resp = MagicMock(status_code=200)
        resp.text = 'Output from saxon processor version 2.0'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'XSLT Injection via Form' in names

    def test_no_vuln_on_clean_page(self):
        page = MockPage(
            url='https://example.com/',
            body='<html>Hello World</html>',
        )
        vulns = self.tester.test(page)
        assert vulns == []

    def test_no_vuln_on_non_xml_endpoint(self):
        page = MockPage(
            url='https://example.com/page',
            body='<html>Regular page</html>',
            parameters={'q': 'search'},
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>No XSLT here</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        assert vulns == []


# ═══════════════════════════════════════════════════════════════════════════════
# ZipSlipTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestZipSlipTester:
    def setup_method(self):
        self.tester = ZipSlipTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Zip Slip'

    def test_archive_upload_form_detected(self):
        page = MockPage(
            url='https://example.com/upload',
            body='<form><input type="file" name="upload"></form>',
            forms=[MockForm(
                action='/upload', method='POST',
                inputs=[MockFormInput(name='upload', input_type='file')],
            )],
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Archive Upload Endpoint Detected' in names

    def test_extraction_indicators(self):
        page = MockPage(
            url='https://example.com/upload',
            body='<html>3 files uploaded successfully. Archive extracted success.</html>',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Unsafe Archive Extraction Indicator' in names

    def test_filename_traversal(self):
        page = MockPage(
            url='https://example.com/upload',
            body='<form><input type="file" name="file"></form>',
            forms=[MockForm(
                action='/upload', method='POST',
                inputs=[MockFormInput(name='file', input_type='file')],
            )],
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>File uploaded successfully</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Zip Slip Path Traversal' in names

    def test_no_vuln_on_clean_page(self):
        page = MockPage(
            url='https://example.com/',
            body='<html>Home page</html>',
        )
        vulns = self.tester.test(page)
        assert vulns == []

    def test_no_vuln_on_non_upload_form(self):
        page = MockPage(
            url='https://example.com/search',
            body='<form><input name="q" type="text"></form>',
            forms=[MockForm(
                action='/search', method='GET',
                inputs=[MockFormInput(name='q', input_type='text')],
            )],
        )
        vulns = self.tester.test(page)
        assert vulns == []


# ═══════════════════════════════════════════════════════════════════════════════
# VHostTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestVHostTester:
    def setup_method(self):
        self.tester = VHostTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Virtual Host Enumeration'

    def test_default_vhost_detected(self):
        page = MockPage(
            url='https://example.com/',
            body='<html><h1>Welcome to nginx!</h1></html>',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Default Virtual Host Page' in names

    def test_wildcard_vhost(self):
        page = MockPage(
            url='https://example.com/',
            body='<html><title>My App</title></html>',
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html><head><title>My App</title></head><body>' + 'A' * 100 + '</body></html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Wildcard Virtual Host' in names

    def test_hidden_vhost_discovered(self):
        page = MockPage(
            url='https://example.com/',
            body='<html><title>Home</title></html>',
        )
        # First call (wildcard test) returns 404, subsequent calls discover a vhost
        resp_404 = MagicMock(status_code=404)
        resp_404.text = 'Not Found'
        resp_404.headers = {}
        resp_vhost = MagicMock(status_code=200)
        resp_vhost.text = '<html><head><title>Admin Panel</title></head><body><form action="/login">' + 'B' * 300 + '</form></body></html>'
        resp_vhost.headers = {}
        # wildcard test returns 404, then vhost enumeration finds one
        with patch.object(
            self.tester, '_make_request',
            side_effect=[resp_404] + [resp_vhost] * 10,
        ):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Hidden Virtual Host Discovered' in names

    def test_no_vuln_on_clean_page(self):
        page = MockPage(
            url='https://example.com/',
            body='<html><title>My App</title></html>',
        )
        resp = MagicMock(status_code=403)
        resp.text = 'Forbidden'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        default_vulns = [v for v in vulns if 'Default' in v['name'] or 'Virtual Host' in v['name']]
        assert len(default_vulns) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# InsecureRandomnessTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestInsecureRandomnessTester:
    def setup_method(self):
        self.tester = InsecureRandomnessTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Insecure Randomness'

    def test_sequential_token_detected(self):
        page = MockPage(
            url='https://example.com/form',
            body='<html>token="123456789" hidden</html>',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Sequential Token Detected' in names

    def test_timestamp_based_token(self):
        page = MockPage(
            url='https://example.com/form',
            body='<html>token="5f3a1b2c" data</html>',
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Timestamp-Based Token Detected' in names

    def test_low_entropy_session_cookie(self):
        page = MockPage(
            url='https://example.com/dashboard',
            body='<html>Dashboard</html>',
            cookies={'sessionid': 'aaaa'},
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Low-Entropy Session Cookie' in names

    def test_no_vuln_on_strong_token(self):
        page = MockPage(
            url='https://example.com/form',
            body='<input name="csrf" value="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0">',
        )
        vulns = self.tester.test(page)
        # Strong token should not trigger sequential or timestamp
        seq_vulns = [v for v in vulns if 'Sequential' in v['name'] or 'Timestamp' in v['name']]
        assert len(seq_vulns) == 0

    def test_no_vuln_on_page_without_tokens(self):
        page = MockPage(
            url='https://example.com/',
            body='<html>Hello World</html>',
        )
        vulns = self.tester.test(page)
        assert vulns == []

    def test_sequential_token_generation_deep(self):
        page = MockPage(
            url='https://example.com/form',
            body='<html>nonce="10000001" data</html>',
        )
        resp1 = MagicMock(status_code=200)
        resp1.text = 'nonce="10000002" data'
        resp2 = MagicMock(status_code=200)
        resp2.text = 'nonce="10000003" data'
        resp3 = MagicMock(status_code=200)
        resp3.text = 'nonce="10000004" data'
        with patch.object(
            self.tester, '_make_request',
            side_effect=[resp1, resp2, resp3],
        ):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Sequential Token Generation' in names


# ═══════════════════════════════════════════════════════════════════════════════
# ReverseProxyMisconfigTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestReverseProxyMisconfigTester:
    def setup_method(self):
        self.tester = ReverseProxyMisconfigTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Reverse Proxy Misconfiguration'

    def test_proxy_headers_detected(self):
        page = MockPage(
            url='https://example.com/',
            body='<html>Home</html>',
            headers={
                'X-Forwarded-For': '10.0.0.1',
                'Via': '1.1 proxy.example.com',
            },
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Reverse Proxy Headers Detected' in names

    def test_path_normalization_bypass(self):
        page = MockPage(
            url='https://example.com/app',
            body='<html>App</html>',
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Path Normalization Bypass' in names

    def test_internal_endpoint_exposed(self):
        page = MockPage(
            url='https://example.com/',
            body='<html>Home</html>',
        )
        resp = MagicMock(status_code=200)
        resp.text = '<html>Server Status: Active connections: 42, requests served: 12345 detailed info here for monitoring</html>'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Internal Endpoint Exposed' in names

    def test_no_vuln_without_proxy_headers(self):
        page = MockPage(
            url='https://example.com/',
            body='<html>Home</html>',
            headers={'Content-Type': 'text/html'},
        )
        resp = MagicMock(status_code=404)
        resp.text = 'Not Found'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='shallow')
        assert vulns == []

    def test_no_vuln_when_paths_return_404(self):
        page = MockPage(
            url='https://example.com/',
            body='<html>Home</html>',
        )
        resp = MagicMock(status_code=404)
        resp.text = 'Not Found'
        resp.headers = {}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page)
        proxy_vulns = [v for v in vulns if 'Path' in v['name'] or 'Internal' in v['name']]
        assert len(proxy_vulns) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# DependencyConfusionTester
# ═══════════════════════════════════════════════════════════════════════════════
class TestDependencyConfusionTester:
    def setup_method(self):
        self.tester = DependencyConfusionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Dependency Confusion'

    def test_internal_package_names_exposed(self):
        page = MockPage(
            url='https://example.com/',
            body=(
                '<script>import dashboard from "@internal/dashboard-utils";\n'
                'import tracker from "@private/analytics-tracker";</script>'
            ),
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Internal Package Names Exposed' in names

    def test_potential_dependency_confusion(self):
        page = MockPage(
            url='https://example.com/',
            body=(
                '<script>import utils from "company-secret-utils";\n'
                'import helper from "my-custom-framework";</script>'
            ),
        )
        vulns = self.tester.test(page)
        names = [v['name'] for v in vulns]
        assert 'Potential Dependency Confusion Target' in names

    def test_package_json_exposed(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>import tool from "company-build-tool";</script>',
        )
        resp = MagicMock(status_code=200)
        resp.text = '{"name": "my-app", "dependencies": {"@corp/secret-lib": "^1.0.0", "express": "^4.18.0"}}'
        resp.headers = {'Content-Type': 'application/json'}
        with patch.object(self.tester, '_make_request', return_value=resp):
            vulns = self.tester.test(page, depth='deep')
        names = [v['name'] for v in vulns]
        assert 'Package Manifest Exposed' in names

    def test_no_vuln_with_only_public_packages(self):
        page = MockPage(
            url='https://example.com/',
            body='<script>import React from "react"; import _ from "lodash";</script>',
        )
        vulns = self.tester.test(page)
        assert vulns == []

    def test_no_vuln_on_page_without_scripts(self):
        page = MockPage(
            url='https://example.com/',
            body='<html><body>No scripts here</body></html>',
        )
        vulns = self.tester.test(page)
        assert vulns == []
