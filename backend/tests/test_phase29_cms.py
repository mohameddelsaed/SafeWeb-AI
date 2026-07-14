"""
Phase 29 — CMS Deep Scanner tests.

Tests for WordPressScanner, DrupalScanner, JoomlaScanner and the CMSTester wrapper.
"""
from unittest.mock import MagicMock

from tests.conftest import MockPage


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_response(status_code=200, text='', headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp


def _make_request_404(*args, **kwargs):
    """Default make_request that always returns 404."""
    return _mock_response(404)


# ═════════════════════════════════════════════════════════════════════════════
# WordPress Scanner
# ═════════════════════════════════════════════════════════════════════════════

class TestWordPressScanner:
    """Tests for the WordPress CMS scanner engine."""

    def _get_scanner(self, make_request=None):
        from apps.scanning.engine.cms.wordpress import WordPressScanner
        return WordPressScanner(make_request or _make_request_404)

    # ── Detection ────────────────────────────────────────────────────────

    def test_is_wordpress_wp_content(self):
        from apps.scanning.engine.cms.wordpress import WordPressScanner
        assert WordPressScanner.is_wordpress('<link href="/wp-content/themes/flavor/style.css">')

    def test_is_wordpress_wp_includes(self):
        from apps.scanning.engine.cms.wordpress import WordPressScanner
        assert WordPressScanner.is_wordpress('<script src="/wp-includes/js/jquery.js"></script>')

    def test_is_wordpress_generator_meta(self):
        from apps.scanning.engine.cms.wordpress import WordPressScanner
        assert WordPressScanner.is_wordpress('<meta name="generator" content="WordPress 6.4">')

    def test_not_wordpress_plain_html(self):
        from apps.scanning.engine.cms.wordpress import WordPressScanner
        assert not WordPressScanner.is_wordpress('<html><body>Hello</body></html>')

    def test_not_wordpress_empty(self):
        from apps.scanning.engine.cms.wordpress import WordPressScanner
        assert not WordPressScanner.is_wordpress('')

    # ── Version detection via meta ───────────────────────────────────────

    def test_version_from_meta_generator(self):
        body = '<meta name="generator" content="WordPress 6.4.2"> <link href="/wp-content/t/x/">'
        scanner = self._get_scanner()
        findings = scanner.scan('https://example.com', body, depth='shallow')
        versions = [f for f in findings if f['check'] == 'wordpress_version']
        assert len(versions) == 1
        assert '6.4.2' in versions[0]['detail']

    # ── Version detection via readme.html ────────────────────────────────

    def test_version_from_readme(self):
        def make_req(method, url, **kwargs):
            if 'readme.html' in url:
                return _mock_response(200, '<br/> Version 6.3.1')
            return _mock_response(404)

        body = '<link href="/wp-content/themes/flavor/x">'  # WP indicator, no meta generator
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        versions = [f for f in findings if f['check'] == 'wordpress_version']
        assert len(versions) == 1
        assert '6.3.1' in versions[0]['detail']

    # ── Plugin enumeration (passive) ─────────────────────────────────────

    def test_plugin_passive_enumeration(self):
        body = '''
        <link href="/wp-content/plugins/contact-form-7/css/style.css">
        <script src="/wp-content/plugins/jetpack/js/main.js"></script>
        <link href="/wp-content/themes/flavor/style.css">
        '''
        scanner = self._get_scanner()
        findings = scanner.scan('https://example.com', body, depth='shallow')
        plugins = [f for f in findings if f['check'] == 'wordpress_plugin']
        slugs = [f['evidence'] for f in plugins]
        assert any('contact-form-7' in s for s in slugs)
        assert any('jetpack' in s for s in slugs)

    # ── Theme enumeration (passive) ──────────────────────────────────────

    def test_theme_passive_enumeration(self):
        body = '<link href="/wp-content/themes/flavor/style.css"><link href="/wp-content/themes/flavor/main.css">'
        scanner = self._get_scanner()
        findings = scanner.scan('https://example.com', body, depth='shallow')
        themes = [f for f in findings if f['check'] == 'wordpress_theme']
        assert any('flavor' in t['evidence'] for t in themes)

    # ── User enumeration (REST API) ──────────────────────────────────────

    def test_user_enum_rest_api(self):
        def make_req(method, url, **kwargs):
            if 'wp-json/wp/v2/users' in url:
                return _mock_response(200, '[{"slug": "admin"}, {"slug": "editor"}]')
            return _mock_response(404)

        body = '<link href="/wp-content/themes/flavor/x">'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        user_findings = [f for f in findings if f['check'] == 'wordpress_user_enum']
        assert len(user_findings) >= 1
        assert 'admin' in user_findings[0]['detail']

    # ── xmlrpc.php ───────────────────────────────────────────────────────

    def test_xmlrpc_enabled(self):
        def make_req(method, url, **kwargs):
            if 'xmlrpc.php' in url:
                return _mock_response(200, '<methodResponse><params><value>...</value></params></methodResponse>')
            return _mock_response(404)

        body = '<link href="/wp-content/themes/flavor/x">'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        xmlrpc = [f for f in findings if f['check'] == 'wordpress_xmlrpc']
        assert len(xmlrpc) == 1

    # ── wp-cron.php ──────────────────────────────────────────────────────

    def test_wp_cron_exposed(self):
        def make_req(method, url, **kwargs):
            if 'wp-cron.php' in url:
                return _mock_response(200, '')
            return _mock_response(404)

        body = '<link href="/wp-content/themes/flavor/x">'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        cron = [f for f in findings if f['check'] == 'wordpress_wp_cron']
        assert len(cron) == 1

    # ── Config backup (deep only) ────────────────────────────────────────

    def test_config_backup_detected(self):
        def make_req(method, url, **kwargs):
            if 'wp-config.php.bak' in url:
                return _mock_response(200, "define('DB_PASSWORD', 'secret'); define('DB_NAME', 'wp');")
            return _mock_response(404)

        body = '<link href="/wp-content/themes/flavor/x">'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='deep')
        backups = [f for f in findings if f['check'] == 'wordpress_config_backup']
        assert len(backups) >= 1
        assert backups[0]['severity'] == 'critical'

    # ── Debug log (deep only) ────────────────────────────────────────────

    def test_debug_log_exposed(self):
        def make_req(method, url, **kwargs):
            if 'debug.log' in url:
                return _mock_response(200, 'PHP Warning: something failed at line 42')
            return _mock_response(404)

        body = '<link href="/wp-content/themes/flavor/x">'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='deep')
        debug = [f for f in findings if f['check'] == 'wordpress_debug_log']
        assert len(debug) == 1
        assert debug[0]['severity'] == 'high'

    # ── Depth gating ─────────────────────────────────────────────────────

    def test_shallow_skips_user_enum(self):
        calls = []

        def make_req(method, url, **kwargs):
            calls.append(url)
            return _mock_response(404)

        body = '<link href="/wp-content/themes/flavor/x">'
        scanner = self._get_scanner(make_req)
        scanner.scan('https://example.com', body, depth='shallow')
        # Shallow should NOT call wp-json/wp/v2/users
        assert not any('wp-json' in c for c in calls)

    def test_medium_skips_aggressive_plugins(self):
        calls = []

        def make_req(method, url, **kwargs):
            calls.append(url)
            return _mock_response(404)

        body = '<link href="/wp-content/themes/flavor/x">'
        scanner = self._get_scanner(make_req)
        scanner.scan('https://example.com', body, depth='medium')
        # Medium should NOT probe plugin readme.txt paths
        assert not any('readme.txt' in c for c in calls)


# ═════════════════════════════════════════════════════════════════════════════
# Drupal Scanner
# ═════════════════════════════════════════════════════════════════════════════

class TestDrupalScanner:
    """Tests for the Drupal CMS scanner engine."""

    def _get_scanner(self, make_request=None):
        from apps.scanning.engine.cms.drupal import DrupalScanner
        return DrupalScanner(make_request or _make_request_404)

    # ── Detection ────────────────────────────────────────────────────────

    def test_is_drupal_settings(self):
        from apps.scanning.engine.cms.drupal import DrupalScanner
        assert DrupalScanner.is_drupal('jQuery.extend(Drupal.settings, {"basePath":"/"});')

    def test_is_drupal_meta_generator(self):
        from apps.scanning.engine.cms.drupal import DrupalScanner
        assert DrupalScanner.is_drupal('<meta name="generator" content="Drupal 10">')

    def test_is_drupal_header(self):
        from apps.scanning.engine.cms.drupal import DrupalScanner
        assert DrupalScanner.is_drupal('', headers={'X-Drupal-Cache': 'HIT'})

    def test_not_drupal(self):
        from apps.scanning.engine.cms.drupal import DrupalScanner
        assert not DrupalScanner.is_drupal('<html><body>Hello</body></html>')

    # ── Version detection ────────────────────────────────────────────────

    def test_version_from_meta(self):
        body = '<meta name="generator" content="Drupal 10.1.5"> <script src="/core/misc/drupal.js"></script>'
        scanner = self._get_scanner()
        findings = scanner.scan('https://example.com', body, depth='shallow')
        versions = [f for f in findings if f['check'] == 'drupal_version']
        assert len(versions) == 1
        assert '10.1.5' in versions[0]['detail']

    def test_version_from_changelog(self):
        def make_req(method, url, **kwargs):
            if 'CHANGELOG.txt' in url:
                return _mock_response(200, 'Drupal 9.5.11 (2023-09-20)')
            return _mock_response(404)

        body = 'jQuery.extend(Drupal.settings, {});'  # Drupal indicator
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='shallow')
        versions = [f for f in findings if f['check'] == 'drupal_version']
        assert len(versions) == 1

    # ── Drupalgeddon 2 ───────────────────────────────────────────────────

    def test_drupalgeddon2_detection(self):
        def make_req(method, url, **kwargs):
            if '/user/register' in url:
                return _mock_response(200, '[{"command":"settings","settings":{}}]')
            return _mock_response(404)

        body = 'jQuery.extend(Drupal.settings, {});'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        dgeddon = [f for f in findings if f['check'] == 'drupalgeddon2']
        assert len(dgeddon) == 1
        assert dgeddon[0]['severity'] == 'critical'

    # ── Drupalgeddon 3 ───────────────────────────────────────────────────

    def test_drupalgeddon3_detection(self):
        def make_req(method, url, **kwargs):
            if '/admin/config' in url:
                return _mock_response(200, '<h1>Configuration</h1>')
            return _mock_response(404)

        body = 'jQuery.extend(Drupal.settings, {});'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        dg3 = [f for f in findings if f['check'] == 'drupalgeddon3']
        assert len(dg3) == 1

    # ── User enumeration ─────────────────────────────────────────────────

    def test_user_enum(self):
        def make_req(method, url, **kwargs):
            if '/user/1' in url:
                return _mock_response(200, '<h1>admin</h1> Member for 3 years')
            return _mock_response(404)

        body = 'jQuery.extend(Drupal.settings, {});'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        users = [f for f in findings if f['check'] == 'drupal_user_enum']
        assert len(users) == 1

    # ── Module enumeration (deep) ────────────────────────────────────────

    def test_module_enum(self):
        def make_req(method, url, **kwargs):
            if 'admin_toolbar' in url and '.info.yml' in url:
                return _mock_response(200, 'name: Admin Toolbar\ntype: module')
            return _mock_response(404)

        body = 'jQuery.extend(Drupal.settings, {});'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='deep')
        mods = [f for f in findings if f['check'] == 'drupal_module']
        assert any('admin_toolbar' in m['detail'] for m in mods)

    # ── Depth gating ─────────────────────────────────────────────────────

    def test_shallow_skips_drupalgeddon(self):
        calls = []

        def make_req(method, url, **kwargs):
            calls.append(url)
            return _mock_response(404)

        body = 'jQuery.extend(Drupal.settings, {});'
        scanner = self._get_scanner(make_req)
        scanner.scan('https://example.com', body, depth='shallow')
        assert not any('/user/register' in c for c in calls)


# ═════════════════════════════════════════════════════════════════════════════
# Joomla Scanner
# ═════════════════════════════════════════════════════════════════════════════

class TestJoomlaScanner:
    """Tests for the Joomla CMS scanner engine."""

    def _get_scanner(self, make_request=None):
        from apps.scanning.engine.cms.joomla import JoomlaScanner
        return JoomlaScanner(make_request or _make_request_404)

    # ── Detection ────────────────────────────────────────────────────────

    def test_is_joomla_generator(self):
        from apps.scanning.engine.cms.joomla import JoomlaScanner
        assert JoomlaScanner.is_joomla('<meta name="generator" content="Joomla! - Open Source CMS">')

    def test_is_joomla_administrator(self):
        from apps.scanning.engine.cms.joomla import JoomlaScanner
        assert JoomlaScanner.is_joomla('<a href="/administrator/">Admin</a>')

    def test_is_joomla_component(self):
        from apps.scanning.engine.cms.joomla import JoomlaScanner
        assert JoomlaScanner.is_joomla('<script src="/components/com_content/js/x.js"></script>')

    def test_not_joomla(self):
        from apps.scanning.engine.cms.joomla import JoomlaScanner
        assert not JoomlaScanner.is_joomla('<html><body>Hello world</body></html>')

    def test_not_joomla_empty(self):
        from apps.scanning.engine.cms.joomla import JoomlaScanner
        assert not JoomlaScanner.is_joomla('')

    # ── Version detection ────────────────────────────────────────────────

    def test_version_from_meta(self):
        body = '<meta name="generator" content="Joomla! - 4.3.2"> <a href="/administrator/">X</a>'
        scanner = self._get_scanner()
        findings = scanner.scan('https://example.com', body, depth='shallow')
        versions = [f for f in findings if f['check'] == 'joomla_version']
        assert len(versions) == 1
        assert '4.3.2' in versions[0]['detail']

    def test_version_from_manifest(self):
        def make_req(method, url, **kwargs):
            if 'joomla.xml' in url:
                return _mock_response(200, '<?xml version="1.0"?><extension><version>4.2.8</version></extension>')
            if '/administrator/' in url:
                return _mock_response(200, '<form>login</form>')
            return _mock_response(404)

        body = '<a href="/administrator/">Admin</a>'  # Joomla indicator
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        versions = [f for f in findings if f['check'] == 'joomla_version']
        assert len(versions) >= 1

    # ── Admin panel ──────────────────────────────────────────────────────

    def test_admin_panel_accessible(self):
        def make_req(method, url, **kwargs):
            if '/administrator/' in url:
                return _mock_response(200, '<form action="login" class="joomla-login">')
            return _mock_response(404)

        body = '<a href="/administrator/">Admin</a>'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='shallow')
        admin = [f for f in findings if f['check'] == 'joomla_admin_panel']
        assert len(admin) == 1

    # ── Component passive enumeration ────────────────────────────────────

    def test_component_passive(self):
        body = '''
        <script src="/components/com_content/js/main.js"></script>
        <link href="/components/com_k2/css/k2.css">
        <a href="/administrator/">Admin</a>
        '''
        scanner = self._get_scanner()
        findings = scanner.scan('https://example.com', body, depth='medium')
        comps = [f for f in findings if f['check'] == 'joomla_component']
        assert any('com_content' in c['detail'] for c in comps)
        assert any('com_k2' in c['detail'] for c in comps)

    # ── Registration check ───────────────────────────────────────────────

    def test_registration_enabled(self):
        def make_req(method, url, **kwargs):
            if 'com_users' in url and 'registration' in url:
                return _mock_response(200, '<h1>User Registration</h1>')
            if '/administrator/' in url:
                return _mock_response(404)
            return _mock_response(404)

        body = '<a href="/administrator/">Admin</a>'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='medium')
        reg = [f for f in findings if f['check'] == 'joomla_registration']
        assert len(reg) == 1

    # ── Config backup (deep) ─────────────────────────────────────────────

    def test_config_backup_detected(self):
        def make_req(method, url, **kwargs):
            if 'configuration.php.bak' in url:
                return _mock_response(200, "public $db = 'joomla'; public $password = 'secret';")
            if '/administrator/' in url:
                return _mock_response(404)
            return _mock_response(404)

        body = '<a href="/administrator/">Admin</a>'
        scanner = self._get_scanner(make_req)
        findings = scanner.scan('https://example.com', body, depth='deep')
        backups = [f for f in findings if f['check'] == 'joomla_config_backup']
        assert len(backups) >= 1
        assert backups[0]['severity'] == 'critical'

    # ── Depth gating ─────────────────────────────────────────────────────

    def test_shallow_skips_components(self):
        calls = []

        def make_req(method, url, **kwargs):
            calls.append(url)
            if '/administrator/' in url:
                return _mock_response(200, '<form>Joomla login</form>')
            return _mock_response(404)

        body = '<a href="/administrator/">Admin</a>'
        scanner = self._get_scanner(make_req)
        scanner.scan('https://example.com', body, depth='shallow')
        # Shallow should not probe component paths
        assert not any('com_users' in c for c in calls)


# ═════════════════════════════════════════════════════════════════════════════
# CMS Tester (BaseTester wrapper)
# ═════════════════════════════════════════════════════════════════════════════

class TestCMSTester:
    """Tests for the CMSTester BaseTester wrapper."""

    def _get_tester(self):
        from apps.scanning.engine.testers.cms_tester import CMSTester
        return CMSTester()

    # ── WordPress integration ────────────────────────────────────────────

    def test_wordpress_findings_converted(self):
        tester = self._get_tester()

        def mock_request(method, url, **kwargs):
            if 'wp-json/wp/v2/users' in url:
                return _mock_response(200, '[{"slug":"admin"}]')
            return _mock_response(404)

        tester._make_request = mock_request

        page = MockPage(
            url='https://example.com',
            body='<meta name="generator" content="WordPress 6.4"> <link href="/wp-content/themes/flavor/x">'
        )
        vulns = tester.test(page, depth='medium')
        assert len(vulns) >= 1
        assert all('name' in v and 'severity' in v for v in vulns)
        assert any('WordPress' in v['name'] for v in vulns)

    # ── Drupal integration ───────────────────────────────────────────────

    def test_drupal_findings_converted(self):
        tester = self._get_tester()
        tester._make_request = _make_request_404

        page = MockPage(
            url='https://example.com',
            body='<meta name="generator" content="Drupal 10.1"> jQuery.extend(Drupal.settings, {});'
        )
        vulns = tester.test(page, depth='shallow')
        assert len(vulns) >= 1
        assert any('Drupal' in v['name'] for v in vulns)

    # ── Joomla integration ───────────────────────────────────────────────

    def test_joomla_findings_converted(self):
        tester = self._get_tester()

        def mock_request(method, url, **kwargs):
            if '/administrator/' in url:
                return _mock_response(200, '<h1>Joomla Login</h1>')
            return _mock_response(404)

        tester._make_request = mock_request

        page = MockPage(
            url='https://example.com',
            body='<meta name="generator" content="Joomla! - 4.3.2"> <a href="/administrator/">Admin</a>'
        )
        vulns = tester.test(page, depth='shallow')
        assert len(vulns) >= 1
        assert any('Joomla' in v['name'] for v in vulns)

    # ── Non-CMS page returns empty ───────────────────────────────────────

    def test_non_cms_returns_empty(self):
        tester = self._get_tester()
        tester._make_request = _make_request_404

        page = MockPage(url='https://example.com', body='<html><body>Hello</body></html>')
        vulns = tester.test(page, depth='medium')
        assert vulns == []

    # ── Empty body returns empty ─────────────────────────────────────────

    def test_empty_body_returns_empty(self):
        tester = self._get_tester()
        tester._make_request = _make_request_404

        page = MockPage(url='https://example.com', body='')
        vulns = tester.test(page, depth='medium')
        assert vulns == []

    # ── Vuln dict structure ──────────────────────────────────────────────

    def test_vuln_has_required_fields(self):
        tester = self._get_tester()
        tester._make_request = _make_request_404

        page = MockPage(
            url='https://example.com',
            body='<meta name="generator" content="WordPress 6.4"> <link href="/wp-content/themes/flavor/x">'
        )
        vulns = tester.test(page, depth='shallow')
        assert len(vulns) >= 1
        required_fields = ['name', 'severity', 'category', 'description', 'impact',
                           'remediation', 'cwe', 'cvss', 'affected_url', 'evidence']
        for vuln in vulns:
            for field_name in required_fields:
                assert field_name in vuln, f'Missing field: {field_name}'

    # ── Tester registration ──────────────────────────────────────────────

    def test_cms_tester_in_all_testers(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        names = [t.TESTER_NAME for t in testers if hasattr(t, 'TESTER_NAME')]
        assert 'CMS Deep Scanner' in names
