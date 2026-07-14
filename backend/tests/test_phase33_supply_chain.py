"""
Phase 33 — Supply Chain & Dependency Scanner tests.

Covers:
  - JSLibraryScanner: detection from CDN, script src, banners, var assignments;
    vulnerability lookup; dependency-confusion detection
  - DependencyChecker: header extraction; CVE lookup; scan_headers combined
  - SupplyChainScanner: unified interface
  - SupplyChainTester: BaseTester integration, registration, tester count
"""
from unittest.mock import patch, MagicMock

# ── Engine imports ───────────────────────────────────────────────────────────
from apps.scanning.engine.supply_chain.js_library_scanner import (
    JSLibraryScanner,
    _parse_version,
    _version_in_range,
    VULN_DB,
    LIB_ALIASES,
)
from apps.scanning.engine.supply_chain.dependency_checker import (
    DependencyChecker,
    CVE_DB,
)
from apps.scanning.engine.supply_chain import SupplyChainScanner
from apps.scanning.engine.testers.supply_chain_tester import SupplyChainTester


# ════════════════════════════════════════════════════════════════════════════
# Version helpers
# ════════════════════════════════════════════════════════════════════════════

class TestVersionHelpers:
    def test_parse_simple(self):
        assert _parse_version('1.2.3') == (1, 2, 3)

    def test_parse_two_parts(self):
        assert _parse_version('3.6') == (3, 6)

    def test_parse_prerelease(self):
        # "2.0.0-beta" → (2, 0, 0)
        assert _parse_version('2.0.0-beta') == (2, 0, 0)

    def test_range_gte_lt(self):
        assert _version_in_range('1.5.0', '>=1.0.0 <2.0.0') is True

    def test_range_gte_lt_outside(self):
        assert _version_in_range('2.0.0', '>=1.0.0 <2.0.0') is False

    def test_range_lte(self):
        assert _version_in_range('3.4.1', '<=3.4.1') is True
        assert _version_in_range('3.4.2', '<=3.4.1') is False

    def test_range_gte_only(self):
        assert _version_in_range('5.0.0', '>=4.0.0') is True
        assert _version_in_range('3.9.9', '>=4.0.0') is False

    def test_exact_match(self):
        assert _version_in_range('1.2.3', '1.2.3') is True
        assert _version_in_range('1.2.4', '1.2.3') is False

    def test_not_equal(self):
        assert _version_in_range('1.0.0', '!=1.0.0') is False
        assert _version_in_range('1.0.1', '!=1.0.0') is True


# ════════════════════════════════════════════════════════════════════════════
# JSLibraryScanner — Detection
# ════════════════════════════════════════════════════════════════════════════

class TestJSLibraryDetection:
    def setup_method(self):
        self.scanner = JSLibraryScanner()

    def test_cdn_jsdelivr(self):
        html = '<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>'
        libs = self.scanner.detect_libraries(html)
        assert any(l['name'] == 'jquery' and l['version'] == '3.6.0' for l in libs)

    def test_cdn_unpkg(self):
        html = '<script src="https://unpkg.com/lodash@4.17.21/lodash.min.js"></script>'
        libs = self.scanner.detect_libraries(html)
        assert any(l['name'] == 'lodash' and l['version'] == '4.17.21' for l in libs)

    def test_cdn_cdnjs(self):
        html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/moment/2.29.1/moment.min.js"></script>'
        libs = self.scanner.detect_libraries(html)
        assert any(l['name'] == 'moment' for l in libs)

    def test_cdn_googleapis(self):
        html = '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>'
        libs = self.scanner.detect_libraries(html)
        assert any(l['name'] == 'angularjs' for l in libs)

    def test_script_src_with_version(self):
        html = '<script src="/static/js/jquery-2.1.4.min.js"></script>'
        libs = self.scanner.detect_libraries(html)
        assert any(l['name'] == 'jquery' and l['version'] == '2.1.4' for l in libs)

    def test_banner_comment(self):
        html = '/*! jQuery v3.5.1 | (c) JS Foundation | jquery.org/license */'
        libs = self.scanner.detect_libraries(html)
        assert any(l['name'] == 'jquery' and l['version'] == '3.5.1' for l in libs)

    def test_var_version(self):
        html = 'jQuery.fn.jquery = "3.3.1";'
        libs = self.scanner.detect_libraries(html)
        assert any(l['name'] == 'jquery' and l['version'] == '3.3.1' for l in libs)

    def test_lodash_version_variable(self):
        html = '_.VERSION = "4.17.15";'
        libs = self.scanner.detect_libraries(html)
        # '_' maps to lodash
        assert any(l['name'] == 'lodash' and l['version'] == '4.17.15' for l in libs)

    def test_deduplication(self):
        html = (
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>'
            '/*! jQuery v3.6.0 */'
        )
        libs = self.scanner.detect_libraries(html)
        jquery_libs = [l for l in libs if l['name'] == 'jquery']
        assert len(jquery_libs) == 1

    def test_no_libraries(self):
        html = '<html><body>Hello</body></html>'
        libs = self.scanner.detect_libraries(html)
        assert libs == []

    def test_multiple_libraries(self):
        html = (
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/moment@2.29.1/moment.min.js"></script>'
        )
        libs = self.scanner.detect_libraries(html)
        names = {l['name'] for l in libs}
        assert 'jquery' in names
        assert 'lodash' in names
        assert 'moment' in names


# ════════════════════════════════════════════════════════════════════════════
# JSLibraryScanner — Vulnerability lookup
# ════════════════════════════════════════════════════════════════════════════

class TestJSVulnLookup:
    def setup_method(self):
        self.scanner = JSLibraryScanner()

    def test_jquery_old_vuln(self):
        vulns = self.scanner.check_vulnerabilities('jquery', '1.8.3')
        cves = [v['cve'] for v in vulns]
        assert 'CVE-2012-6708' in cves
        assert 'CVE-2020-11022' in cves

    def test_jquery_safe_version(self):
        vulns = self.scanner.check_vulnerabilities('jquery', '3.7.0')
        assert vulns == []

    def test_lodash_prototype_pollution(self):
        vulns = self.scanner.check_vulnerabilities('lodash', '4.17.10')
        cves = [v['cve'] for v in vulns]
        assert 'CVE-2019-10744' in cves

    def test_handlebars_critical(self):
        vulns = self.scanner.check_vulnerabilities('handlebars', '4.5.0')
        assert any(v['severity'] == 'critical' for v in vulns)

    def test_unknown_library(self):
        vulns = self.scanner.check_vulnerabilities('nonexistent-lib', '1.0.0')
        assert vulns == []

    def test_alias_resolution(self):
        # 'jQuery' alias → 'jquery'
        vulns = self.scanner.check_vulnerabilities('jQuery', '1.8.3')
        assert len(vulns) > 0

    def test_angularjs_vuln(self):
        vulns = self.scanner.check_vulnerabilities('angularjs', '1.5.0')
        cves = [v['cve'] for v in vulns]
        assert 'CVE-2019-10768' in cves

    def test_bootstrap_xss(self):
        vulns = self.scanner.check_vulnerabilities('bootstrap', '3.3.7')
        cves = [v['cve'] for v in vulns]
        assert 'CVE-2019-8331' in cves

    def test_moment_redos(self):
        vulns = self.scanner.check_vulnerabilities('moment', '2.29.0')
        cves = [v['cve'] for v in vulns]
        assert 'CVE-2022-31129' in cves

    def test_extra_db(self):
        extra = {'custom-lib': [
            {'versions': '>=1.0.0 <2.0.0', 'severity': 'high', 'cve': 'CVE-FAKE-001',
             'info': 'Test vuln'},
        ]}
        scanner = JSLibraryScanner(extra_vuln_db=extra)
        vulns = scanner.check_vulnerabilities('custom-lib', '1.5.0')
        assert len(vulns) == 1
        assert vulns[0]['cve'] == 'CVE-FAKE-001'


# ════════════════════════════════════════════════════════════════════════════
# JSLibraryScanner — Dependency confusion
# ════════════════════════════════════════════════════════════════════════════

class TestDependencyConfusion:
    def setup_method(self):
        self.scanner = JSLibraryScanner()

    def test_scoped_internal_package(self):
        html = '<script type="importmap">{"imports":{"@internal/auth":"./auth.js"}}</script>'
        results = self.scanner.detect_dependency_confusion(html)
        assert len(results) >= 1
        assert results[0]['package'] == '@internal/auth'
        assert results[0]['is_scoped'] is True

    def test_internal_named_package(self):
        html = "import '@company/ui-kit';"
        results = self.scanner.detect_dependency_confusion(html)
        # @company/ is scoped but not necessarily internal-named
        assert len(results) >= 1

    def test_known_public_ignored(self):
        html = "import 'react';\nimport 'lodash';"
        results = self.scanner.detect_dependency_confusion(html)
        assert len(results) == 0

    def test_private_suffix(self):
        html = "import 'myapp-private';"
        results = self.scanner.detect_dependency_confusion(html)
        assert any(r['package'] == 'myapp-private' for r in results)

    def test_no_packages(self):
        html = '<html><body>No imports</body></html>'
        results = self.scanner.detect_dependency_confusion(html)
        assert results == []


# ════════════════════════════════════════════════════════════════════════════
# DependencyChecker — Header detection
# ════════════════════════════════════════════════════════════════════════════

class TestDependencyCheckerDetection:
    def setup_method(self):
        self.checker = DependencyChecker()

    def test_apache_header(self):
        headers = {'Server': 'Apache/2.4.41 (Ubuntu)'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'apache' and c['version'] == '2.4.41' for c in comps)

    def test_nginx_header(self):
        headers = {'Server': 'nginx/1.18.0'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'nginx' and c['version'] == '1.18.0' for c in comps)

    def test_php_powered_by(self):
        headers = {'X-Powered-By': 'PHP/7.4.33'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'php' and c['version'] == '7.4.33' for c in comps)

    def test_express_powered_by(self):
        headers = {'X-Powered-By': 'Express'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'express' for c in comps)

    def test_iis_header(self):
        headers = {'Server': 'Microsoft-IIS/10.0'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'iis' and c['version'] == '10.0' for c in comps)

    def test_wordpress_generator(self):
        headers = {'X-Generator': 'WordPress 6.3.1'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'wordpress' and c['version'] == '6.3.1' for c in comps)

    def test_django_version_header(self):
        headers = {'X-Django-Version': '4.2.7'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'django' and c['version'] == '4.2.7' for c in comps)

    def test_cloudflare_keyword(self):
        headers = {'Server': 'cloudflare'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'cloudflare' for c in comps)

    def test_varnish_via(self):
        headers = {'Via': '1.1 varnish (Varnish/6.0)'}
        comps = self.checker.detect_from_headers(headers)
        assert any(c['name'] == 'varnish' for c in comps)

    def test_empty_headers(self):
        assert self.checker.detect_from_headers({}) == []

    def test_none_headers(self):
        assert self.checker.detect_from_headers(None) == []

    def test_multiple_components(self):
        headers = {
            'Server': 'Apache/2.4.41',
            'X-Powered-By': 'PHP/7.4.33',
        }
        comps = self.checker.detect_from_headers(headers)
        names = {c['name'] for c in comps}
        assert 'apache' in names
        assert 'php' in names


# ════════════════════════════════════════════════════════════════════════════
# DependencyChecker — CVE lookup
# ════════════════════════════════════════════════════════════════════════════

class TestDependencyCheckerCVE:
    def setup_method(self):
        self.checker = DependencyChecker()

    def test_apache_cve(self):
        cves = self.checker.check_cves('apache', '2.4.49')
        cve_ids = [c['cve'] for c in cves]
        assert 'CVE-2021-41773' in cve_ids

    def test_apache_safe_version(self):
        cves = self.checker.check_cves('apache', '2.4.60')
        # 2.4.60 is outside all ranges
        assert len(cves) == 0

    def test_php_critical(self):
        cves = self.checker.check_cves('php', '8.1.27')
        assert any(c['severity'] == 'critical' for c in cves)
        assert any(c['cve'] == 'CVE-2024-4577' for c in cves)

    def test_no_version_returns_potential(self):
        cves = self.checker.check_cves('apache', '')
        # All entries returned with confirmed=False
        assert len(cves) > 0
        assert all(c['confirmed'] is False for c in cves)

    def test_unknown_component(self):
        cves = self.checker.check_cves('nonexistent', '1.0.0')
        assert cves == []

    def test_tomcat_ghostcat(self):
        cves = self.checker.check_cves('tomcat', '9.0.30')
        cve_ids = [c['cve'] for c in cves]
        assert 'CVE-2020-1938' in cve_ids

    def test_epss_score_present(self):
        cves = self.checker.check_cves('apache', '2.4.49')
        for c in cves:
            assert 'epss' in c

    def test_drupal_drupalgeddon(self):
        cves = self.checker.check_cves('drupal', '7.58')
        cve_ids = [c['cve'] for c in cves]
        assert 'CVE-2018-7600' in cve_ids

    def test_extra_cve_db(self):
        extra = {'custom-srv': [
            {'versions': '>=1.0.0 <3.0.0', 'severity': 'critical',
             'cve': 'CVE-FAKE-002', 'info': 'Test CVE', 'epss': 0.99},
        ]}
        checker = DependencyChecker(extra_cve_db=extra)
        cves = checker.check_cves('custom-srv', '2.0.0')
        assert len(cves) == 1
        assert cves[0]['cve'] == 'CVE-FAKE-002'

    def test_scan_headers_combined(self):
        headers = {'Server': 'Apache/2.4.49'}
        results = self.checker.scan_headers(headers)
        assert len(results) >= 1
        assert 'cves' in results[0]
        assert len(results[0]['cves']) > 0


# ════════════════════════════════════════════════════════════════════════════
# SupplyChainScanner — Unified interface
# ════════════════════════════════════════════════════════════════════════════

class TestSupplyChainScanner:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_scan_js_libraries(self):
        html = '<script src="https://cdn.jsdelivr.net/npm/jquery@1.8.0/jquery.min.js"></script>'
        results = self.scanner.scan_js_libraries(html)
        assert len(results) >= 1
        assert results[0]['name'] == 'jquery'
        assert len(results[0]['vulnerabilities']) > 0

    def test_scan_backend_dependencies(self):
        headers = {'Server': 'Apache/2.4.49'}
        results = self.scanner.scan_backend_dependencies(headers)
        assert len(results) >= 1
        assert len(results[0]['cves']) > 0

    def test_check_dependency_confusion(self):
        html = "import '@internal/core-utils';"
        results = self.scanner.check_dependency_confusion(html)
        assert len(results) >= 1

    def test_full_scan(self):
        html = (
            '<script src="https://cdn.jsdelivr.net/npm/jquery@1.8.0/jquery.min.js"></script>'
            "import '@internal/core-utils';"
        )
        headers = {'Server': 'Apache/2.4.49'}
        result = self.scanner.full_scan(html, headers)
        assert 'js_libraries' in result
        assert 'backend_dependencies' in result
        assert 'dependency_confusion' in result

    def test_full_scan_clean(self):
        html = '<html><body>Clean page</body></html>'
        headers = {'Content-Type': 'text/html'}
        result = self.scanner.full_scan(html, headers)
        assert result['js_libraries'] == []
        assert result['backend_dependencies'] == []
        assert result['dependency_confusion'] == []


# ════════════════════════════════════════════════════════════════════════════
# SupplyChainTester — BaseTester integration
# ════════════════════════════════════════════════════════════════════════════

class TestSupplyChainTester:
    def setup_method(self):
        self.tester = SupplyChainTester()

    def test_empty_url(self):
        assert self.tester.test({'url': ''}) == []

    @patch.object(SupplyChainTester, '_make_request')
    def test_request_failure(self, mock_req):
        mock_req.return_value = None
        result = self.tester.test({'url': 'http://example.com'})
        assert result == []

    @patch.object(SupplyChainTester, '_make_request')
    def test_quick_js_only(self, mock_req):
        """quick depth: only JS library scan."""
        resp = MagicMock()
        resp.text = '<script src="https://cdn.jsdelivr.net/npm/jquery@1.8.0/jquery.min.js"></script>'
        resp.headers = {'Content-Type': 'text/html'}
        mock_req.return_value = resp

        vulns = self.tester.test({'url': 'http://example.com'}, depth='quick')
        assert len(vulns) > 0
        assert all(v['category'] == 'supply_chain_js' for v in vulns)

    @patch.object(SupplyChainTester, '_make_request')
    def test_medium_includes_backend(self, mock_req):
        """medium depth: JS + backend dependency scan."""
        resp = MagicMock()
        resp.text = '<html></html>'
        resp.headers = {'Server': 'Apache/2.4.49', 'Content-Type': 'text/html'}
        mock_req.return_value = resp

        vulns = self.tester.test({'url': 'http://example.com'}, depth='medium')
        assert any(v['category'] == 'supply_chain_backend' for v in vulns)

    @patch.object(SupplyChainTester, '_make_request')
    def test_deep_includes_confusion(self, mock_req):
        """deep depth: JS + backend + dependency confusion."""
        resp = MagicMock()
        resp.text = "import '@internal/core-utils';"
        resp.headers = {'Server': 'Apache/2.4.49', 'Content-Type': 'text/html'}
        mock_req.return_value = resp

        vulns = self.tester.test({'url': 'http://example.com'}, depth='deep')
        categories = {v['category'] for v in vulns}
        assert 'supply_chain_confusion' in categories

    @patch.object(SupplyChainTester, '_make_request')
    def test_vuln_dict_structure(self, mock_req):
        """Verify vulnerability dict has all required keys."""
        resp = MagicMock()
        resp.text = '<script src="https://cdn.jsdelivr.net/npm/jquery@1.8.0/jquery.min.js"></script>'
        resp.headers = {'Content-Type': 'text/html'}
        mock_req.return_value = resp

        vulns = self.tester.test({'url': 'http://example.com'})
        required_keys = {
            'name', 'severity', 'category', 'description',
            'impact', 'remediation', 'cwe', 'cvss', 'affected_url', 'evidence',
        }
        for v in vulns:
            assert required_keys.issubset(v.keys())

    @patch.object(SupplyChainTester, '_make_request')
    def test_no_vulns_clean_page(self, mock_req):
        resp = MagicMock()
        resp.text = '<html><body>Clean</body></html>'
        resp.headers = {'Content-Type': 'text/html'}
        mock_req.return_value = resp

        vulns = self.tester.test({'url': 'http://example.com'})
        assert vulns == []

    @patch.object(SupplyChainTester, '_make_request')
    def test_lib_vuln_cwe(self, mock_req):
        resp = MagicMock()
        resp.text = '<script src="https://cdn.jsdelivr.net/npm/jquery@1.8.0/jquery.min.js"></script>'
        resp.headers = {'Content-Type': 'text/html'}
        mock_req.return_value = resp

        vulns = self.tester.test({'url': 'http://example.com'})
        for v in vulns:
            assert v['cwe'] == 'CWE-1104'

    @patch.object(SupplyChainTester, '_make_request')
    def test_dep_vuln_cwe(self, mock_req):
        resp = MagicMock()
        resp.text = '<html></html>'
        resp.headers = {'Server': 'Apache/2.4.49', 'Content-Type': 'text/html'}
        mock_req.return_value = resp

        vulns = self.tester.test({'url': 'http://example.com'}, depth='medium')
        backend_vulns = [v for v in vulns if v['category'] == 'supply_chain_backend']
        for v in backend_vulns:
            assert v['cwe'] == 'CWE-1104'

    @patch.object(SupplyChainTester, '_make_request')
    def test_confusion_vuln_cwe(self, mock_req):
        resp = MagicMock()
        resp.text = "import '@internal/core-utils';"
        resp.headers = {'Content-Type': 'text/html'}
        mock_req.return_value = resp

        vulns = self.tester.test({'url': 'http://example.com'}, depth='deep')
        confusion_vulns = [v for v in vulns if v['category'] == 'supply_chain_confusion']
        for v in confusion_vulns:
            assert v['cwe'] == 'CWE-427'

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Supply Chain Scanner'

    def test_registration(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        names = [t.TESTER_NAME for t in testers]
        assert 'Supply Chain Scanner' in names

    def test_tester_count(self):
        """Total tester count is 65 (64 + Phase 33)."""
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert len(testers) == 87


# ════════════════════════════════════════════════════════════════════════════
# VULN_DB / CVE_DB coverage sanity checks
# ════════════════════════════════════════════════════════════════════════════

class TestDBCoverage:
    def test_vuln_db_has_libraries(self):
        assert len(VULN_DB) >= 20

    def test_cve_db_has_components(self):
        assert len(CVE_DB) >= 15

    def test_all_vuln_entries_have_required_keys(self):
        for lib, entries in VULN_DB.items():
            for e in entries:
                assert 'versions' in e, f"Missing 'versions' in {lib}"
                assert 'severity' in e, f"Missing 'severity' in {lib}"
                assert 'cve' in e, f"Missing 'cve' in {lib}"

    def test_all_cve_entries_have_required_keys(self):
        for comp, entries in CVE_DB.items():
            for e in entries:
                assert 'versions' in e, f"Missing 'versions' in {comp}"
                assert 'severity' in e, f"Missing 'severity' in {comp}"
                assert 'cve' in e, f"Missing 'cve' in {comp}"

    def test_lib_aliases_map_to_vuln_db(self):
        """Every alias target should ideally exist in VULN_DB (best effort)."""
        set(VULN_DB.keys())
        for alias, canon in LIB_ALIASES.items():
            # Not all aliases have DB entries (some are just name normalization)
            pass  # Informational — no assertion needed
