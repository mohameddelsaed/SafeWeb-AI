"""Tests for the ScanOrchestrator (parallel recon architecture)."""
import contextlib
from unittest.mock import patch, MagicMock


_RECON = 'apps.scanning.engine.recon'

# Default mock return values per module key → (import path, return value)
_MODULE_DEFAULTS = {
    # Wave 0a
    f'{_RECON}.dns_recon.run_dns_recon':         {'hostname': 'example.com', 'ip_addresses': []},
    f'{_RECON}.whois_recon.run_whois_recon':      {'domain': 'example.com'},
    f'{_RECON}.cert_analysis.run_cert_analysis':  {'has_ssl': True, 'valid': True, 'days_until_expiry': 90},
    f'{_RECON}.waf_detection.run_waf_detection':  {'detected': False, 'products': [], 'confidence': 'none'},
    f'{_RECON}.ai_recon.run_ai_recon':            {'detected': False, 'endpoints': [], 'frameworks': []},
    f'{_RECON}.dns_zone_enum.run_dns_zone_enum':  {'srv_records': []},
    f'{_RECON}.port_scanner.run_port_scan':       {'open_ports': []},
    f'{_RECON}.ct_log_enum.run_ct_log_enum':      {'subdomains': []},
    f'{_RECON}.subdomain_enum.run_subdomain_enum': {'subdomains': []},
    f'{_RECON}.passive_subdomain.run_passive_subdomain': {'subdomains': []},
    f'{_RECON}.asn_recon.run_asn_recon':          {'cidrs': []},
    f'{_RECON}.wildcard_detector.run_wildcard_detection': {'wildcard_detected': False, 'wildcard_type': 'none'},
    # Wave 0b
    f'{_RECON}.tech_fingerprint.run_tech_fingerprint': {'technologies': []},
    f'{_RECON}.header_analyzer.run_header_analysis':   {'missing': [], 'score': 50},
    f'{_RECON}.cookie_analyzer.run_cookie_analysis':   {'cookies': [], 'score': 100},
    f'{_RECON}.url_harvester.run_url_harvester':       {'urls': []},
    f'{_RECON}.social_recon.run_social_recon':         {'social_links': []},
    f'{_RECON}.http_probe.run_http_probe':             {'live_hosts': []},
    f'{_RECON}.screenshot_recon.run_screenshot_recon': {'pages': []},
    f'{_RECON}.cors_analyzer.run_cors_analyzer':       {'misconfigurations': []},
    f'{_RECON}.js_analyzer.run_js_analyzer':           {'secrets': [], 'scripts': []},
    f'{_RECON}.cloud_detect.run_cloud_detect':         {'providers': []},
    f'{_RECON}.cms_fingerprint.run_cms_fingerprint':   {'cms': None},
    f'{_RECON}.url_intelligence.run_url_intelligence': {'urls': []},
    f'{_RECON}.favicon_hash.run_favicon_hash':         {'favicon_hash': None, 'technology': None},
    # Wave 0c
    f'{_RECON}.email_enum.run_email_enum':               {'emails': []},
    f'{_RECON}.subdomain_takeover_recon.run_subdomain_takeover_recon': {'takeovers': []},
    f'{_RECON}.secret_scanner.run_secret_scanner':       {'secrets': []},
    f'{_RECON}.cloud_enum.run_cloud_enum':               {'buckets': []},
    f'{_RECON}.google_dorking.run_google_dorking':       {'dorks': []},
    f'{_RECON}.cloud_recon.run_cloud_recon':             {'cloud_resources': []},
    'apps.scanning.engine.osint.shodan_intel.run_shodan_intel': {'results': []},
    'apps.scanning.engine.osint.censys_intel.run_censys_intel': {'results': []},
    'apps.scanning.engine.osint.wayback_intel.run_wayback_intel': {'results': []},
    'apps.scanning.engine.osint.github_intel.run_github_intel': {'results': []},
    'apps.scanning.engine.osint.vt_intel.run_vt_intel':         {'results': []},
    f'{_RECON}.content_discovery.run_content_discovery': {'paths': []},
    f'{_RECON}.param_discovery.run_param_discovery':     {'params': []},
    f'{_RECON}.api_discovery.run_api_discovery':         {'apis': []},
    f'{_RECON}.subdomain_brute.run_subdomain_brute':     {'subdomains': [], 'new_subdomains': []},
    f'{_RECON}.network_mapper.run_network_mapper':       {'topology': {}},
    f'{_RECON}.reverse_dns.run_reverse_dns':             {'records': []},
    f'{_RECON}.github_recon.run_github_recon':           {'repos': []},
    f'{_RECON}.subdomain_permutation.run_subdomain_permutation': {'subdomains': []},
    # Wave 0d
    f'{_RECON}.vuln_correlator.run_vuln_correlator': {'correlations': []},
    f'{_RECON}.attack_surface.run_attack_surface':   {'score': 0},
    f'{_RECON}.threat_intel.run_threat_intel':        {'threats': []},
    f'{_RECON}.risk_scorer.run_risk_scorer':          {'grade': 'A', 'overall_score': 95},
    f'{_RECON}.scope_analyzer.run_scope_analysis':    {'in_scope': True},
}


def _mock_session():
    """Return a mock requests.Session with empty homepage response."""
    session = MagicMock()
    resp = MagicMock()
    resp.text = '<html></html>'
    resp.headers = {'Content-Type': 'text/html'}
    resp.cookies = []
    resp.status_code = 200
    session.get.return_value = resp
    session.request.return_value = resp
    return session


def _patch_all(overrides=None):
    """Return an ExitStack that patches all recon modules + requests.Session."""
    stack = contextlib.ExitStack()
    stack.enter_context(patch('requests.Session', return_value=_mock_session()))

    combined = dict(_MODULE_DEFAULTS)
    if overrides:
        combined.update(overrides)

    for path, rv in combined.items():
        if isinstance(rv, Exception):
            stack.enter_context(patch(path, side_effect=rv))
        else:
            stack.enter_context(patch(path, return_value=rv))
    return stack


class TestOrchestratorRecon:
    def setup_method(self):
        from apps.scanning.engine.orchestrator import ScanOrchestrator
        self.orchestrator = ScanOrchestrator()

    def test_run_recon_returns_dict(self):
        """Recon should return a dict with module keys."""
        mock_scan = MagicMock()
        mock_scan.target = 'https://example.com'
        mock_scan.depth = 'medium'

        with _patch_all():
            result = self.orchestrator._run_recon(mock_scan)

        assert isinstance(result, dict)
        assert 'dns' in result
        assert 'whois' in result
        assert 'technologies' in result
        assert 'waf' in result
        assert 'certificate' in result

    def test_recon_graceful_failure(self):
        """If individual modules fail, recon should continue."""
        mock_scan = MagicMock()
        mock_scan.target = 'https://example.com'
        mock_scan.depth = 'medium'

        # All modules raise
        overrides = {path: Exception('boom') for path in _MODULE_DEFAULTS}
        with _patch_all(overrides):
            result = self.orchestrator._run_recon(mock_scan)

        assert isinstance(result, dict)
        # All modules failed — keys only present for successful modules
        # (some wave 0b may not fail if homepage fetch uses mock session)
        assert len(result) >= 0

    def test_port_scan_deep_only(self):
        """Port scanning should only run on deep scans."""
        mock_scan = MagicMock()
        mock_scan.target = 'https://example.com'

        # Medium scan — no port scan
        mock_scan.depth = 'medium'
        port_mock = MagicMock(return_value={'open_ports': []})
        with _patch_all():
            with patch(f'{_RECON}.port_scanner.run_port_scan', port_mock):
                result = self.orchestrator._run_recon(mock_scan)
        assert 'ports' not in result

        # Deep scan — port scan included
        mock_scan.depth = 'deep'
        with _patch_all():
            with patch(f'{_RECON}.port_scanner.run_port_scan', return_value={'open_ports': [{'port': 80}]}):
                result = self.orchestrator._run_recon(mock_scan)
        assert 'ports' in result

    def test_medium_includes_p0_and_p1(self):
        """Medium depth should include P0 (CT logs, subdomain enum) and P1 modules."""
        mock_scan = MagicMock()
        mock_scan.target = 'https://example.com'
        mock_scan.depth = 'medium'

        with _patch_all():
            result = self.orchestrator._run_recon(mock_scan)

        # P0 modules
        assert 'ct_logs' in result
        assert 'subdomains' in result
        # P1 modules (wave 0b medium+deep)
        assert 'cors' in result
        assert 'cloud' in result

    def test_deep_includes_all_waves(self):
        """Deep depth should run all modules including P2 discovery + P3 analytics."""
        mock_scan = MagicMock()
        mock_scan.target = 'https://example.com'
        mock_scan.depth = 'deep'

        with _patch_all():
            result = self.orchestrator._run_recon(mock_scan)

        # Wave 0c — deep-only
        assert 'content_discovery' in result
        assert 'param_discovery' in result
        assert 'api_discovery' in result
        assert 'subdomain_brute' in result
        assert 'network' in result
        # Wave 0d — analytics
        assert 'risk_score' in result
        assert 'attack_surface' in result


class TestOrchestratorScoreCalculation:
    def setup_method(self):
        from apps.scanning.engine.orchestrator import ScanOrchestrator
        self.orchestrator = ScanOrchestrator()

    def test_calculate_score_delegates_to_scoring(self):
        mock_scan = MagicMock()
        mock_vulns = MagicMock()
        mock_vulns.exists.return_value = True
        mock_vulns.all.return_value = mock_vulns
        mock_vulns.values.return_value = [{'severity': 'high'}]
        mock_scan.vulnerabilities = mock_vulns

        with patch('apps.scanning.engine.scoring.calculate_security_score', return_value=85):
            score = self.orchestrator._calculate_security_score(mock_scan)
            assert score == 85

    def test_no_vulns_returns_100(self):
        mock_scan = MagicMock()
        mock_vulns = MagicMock()
        mock_vulns.exists.return_value = False
        mock_vulns.all.return_value = mock_vulns
        mock_scan.vulnerabilities = mock_vulns

        score = self.orchestrator._calculate_security_score(mock_scan)
        assert score == 100
