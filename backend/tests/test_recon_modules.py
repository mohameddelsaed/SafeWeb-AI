"""Tests for all recon modules — import, standardised format, and basic functionality."""
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _assert_standard_format(result: dict, module_name: str):
    """Assert the result dict contains the standardised keys from _base.py."""
    assert isinstance(result, dict), f'{module_name}: result is not a dict'
    assert 'findings' in result, f'{module_name}: missing findings key'
    assert 'metadata' in result, f'{module_name}: missing metadata key'
    assert 'errors' in result, f'{module_name}: missing errors key'
    assert 'stats' in result, f'{module_name}: missing stats key'
    assert isinstance(result['findings'], list)
    assert isinstance(result['metadata'], dict)
    assert isinstance(result['errors'], list)
    assert isinstance(result['stats'], dict)
    assert result['metadata']['module'] == module_name


# ---------------------------------------------------------------------------
# _base.py unit tests
# ---------------------------------------------------------------------------
class TestBase:
    def test_create_result(self):
        from apps.scanning.engine.recon._base import create_result
        r = create_result('test_mod', 'https://example.com', 'deep')
        assert r['metadata']['module'] == 'test_mod'
        assert r['metadata']['target'] == 'https://example.com'
        assert r['metadata']['depth'] == 'deep'
        assert r['findings'] == []
        assert r['errors'] == []

    def test_add_finding(self):
        from apps.scanning.engine.recon._base import create_result, add_finding
        r = create_result('test_mod', 'https://example.com')
        add_finding(r, {'type': 'test', 'detail': 'ok'})
        assert len(r['findings']) == 1
        assert r['findings'][0]['type'] == 'test'

    def test_finalize_result(self):
        import time
        from apps.scanning.engine.recon._base import create_result, finalize_result
        r = create_result('test_mod', 'https://example.com')
        start = time.time()
        finalized = finalize_result(r, start)
        assert finalized is r
        assert r['metadata']['completed_at'] is not None
        assert r['stats']['duration_seconds'] >= 0

    def test_extract_hostname(self):
        from apps.scanning.engine.recon._base import extract_hostname
        assert extract_hostname('https://sub.example.com:8080/path') == 'sub.example.com'
        assert extract_hostname('http://example.com') == 'example.com'

    def test_extract_root_domain(self):
        from apps.scanning.engine.recon._base import extract_root_domain
        assert extract_root_domain('sub.example.com') in ('example.com',)

    def test_load_data_lines(self):
        from apps.scanning.engine.recon._base import load_data_lines
        lines = load_data_lines('subdomain_wordlist_100.txt')
        assert isinstance(lines, list)
        assert len(lines) > 0

    def test_load_json_data(self):
        from apps.scanning.engine.recon._base import load_json_data
        data = load_json_data('waf_signatures.json')
        assert isinstance(data, (dict, list))


# ---------------------------------------------------------------------------
# Upgraded modules — standardised format tests
# ---------------------------------------------------------------------------
class TestDNSReconFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.dns_recon import run_dns_recon
        result = run_dns_recon('https://example.com', 'shallow')
        _assert_standard_format(result, 'dns_recon')
        # Legacy keys preserved
        assert 'hostname' in result
        assert 'ip_addresses' in result


class TestWhoisReconFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.whois_recon import run_whois_recon
        with patch('socket.create_connection') as mock_conn:
            mock_sock = MagicMock()
            mock_sock.recv.side_effect = [
                b'Domain Name: example.com\nRegistrar: Test Registrar\n', b'',
            ]
            mock_conn.return_value.__enter__ = lambda s: mock_sock
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            result = run_whois_recon('https://example.com')
        _assert_standard_format(result, 'whois_recon')
        assert 'domain' in result


class TestPortScannerFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.port_scanner import run_port_scan
        with patch('socket.gethostbyname', return_value='93.184.216.34'):
            result = run_port_scan('https://example.com', 'shallow', timeout=0.01)
        _assert_standard_format(result, 'port_scanner')
        assert 'open_ports' in result
        assert 'hostname' in result


class TestTechFingerprintFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.tech_fingerprint import run_tech_fingerprint
        result = run_tech_fingerprint(
            target_url='https://example.com',
            response_headers={'Server': 'nginx'},
            response_body='<html></html>',
            cookies={},
        )
        _assert_standard_format(result, 'tech_fingerprint')
        assert 'technologies' in result


class TestWAFDetectionFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.waf_detection import run_waf_detection
        mock_fn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = ''
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.get_dict.return_value = {}
        mock_fn.return_value = mock_resp
        result = run_waf_detection('https://example.com', mock_fn)
        _assert_standard_format(result, 'waf_detection')
        assert 'detected' in result
        assert 'products' in result


class TestCertAnalysisFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.cert_analysis import run_cert_analysis
        result = run_cert_analysis('https://127.0.0.1:0')
        _assert_standard_format(result, 'cert_analysis')
        assert 'has_ssl' in result


class TestHeaderAnalyzerFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers={'Content-Type': 'text/html'},
        )
        _assert_standard_format(result, 'header_analysis')
        assert 'missing' in result
        assert 'score' in result


class TestCookieAnalyzerFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.cookie_analyzer import run_cookie_analysis
        result = run_cookie_analysis(
            target_url='https://example.com',
            cookies={'test': 'value'},
        )
        _assert_standard_format(result, 'cookie_analysis')
        assert 'score' in result


class TestAIReconFormat:
    def test_standard_format(self):
        from apps.scanning.engine.recon.ai_recon import run_ai_recon
        with patch('requests.Session') as mock_cls:
            sess = MagicMock()
            resp = MagicMock()
            resp.status_code = 404
            resp.headers = {}
            resp.text = '<html></html>'
            sess.get.return_value = resp
            mock_cls.return_value = sess
            result = run_ai_recon('https://example.com')
        _assert_standard_format(result, 'ai_recon')
        assert 'detected' in result
        assert 'endpoints' in result


# ---------------------------------------------------------------------------
# P0 new modules
# ---------------------------------------------------------------------------
class TestCTLogEnum:
    def test_standard_format(self):
        from apps.scanning.engine.recon.ct_log_enum import run_ct_log_enum
        with patch('requests.get') as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=MagicMock(return_value=[
                    {'common_name': 'www.example.com', 'name_value': 'www.example.com'},
                ]),
            )
            result = run_ct_log_enum('https://example.com', 'shallow')
        _assert_standard_format(result, 'ct_log_enum')


class TestSubdomainEnum:
    def test_standard_format(self):
        from apps.scanning.engine.recon.subdomain_enum import run_subdomain_enum
        with patch('socket.getaddrinfo', side_effect=OSError):
            result = run_subdomain_enum('https://example.com', 'quick')
        _assert_standard_format(result, 'subdomain_enum')


class TestURLHarvester:
    def test_standard_format(self):
        from apps.scanning.engine.recon.url_harvester import run_url_harvester
        result = run_url_harvester(
            target_url='https://example.com',
            response_body='<a href="/page">link</a>',
        )
        _assert_standard_format(result, 'url_harvester')


class TestJSAnalyzer:
    def test_standard_format(self):
        from apps.scanning.engine.recon.js_analyzer import run_js_analyzer
        result = run_js_analyzer(
            target_url='https://example.com',
            js_content='var apiKey = "sk_test_12345";',
        )
        _assert_standard_format(result, 'js_analyzer')


# ---------------------------------------------------------------------------
# P1 new modules
# ---------------------------------------------------------------------------
class TestCloudDetect:
    def test_standard_format(self):
        from apps.scanning.engine.recon.cloud_detect import run_cloud_detect
        result = run_cloud_detect(
            target_url='https://example.com',
            response_headers={'Server': 'AmazonS3'},
        )
        _assert_standard_format(result, 'cloud_detect')


class TestCORSAnalyzer:
    def test_standard_format(self):
        from apps.scanning.engine.recon.cors_analyzer import run_cors_analyzer
        mock_fn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_fn.return_value = mock_resp
        result = run_cors_analyzer('https://example.com', mock_fn)
        _assert_standard_format(result, 'cors_analyzer')


class TestContentDiscovery:
    def test_standard_format(self):
        from apps.scanning.engine.recon.content_discovery import run_content_discovery
        mock_fn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.headers = {}
        mock_fn.return_value = mock_resp
        result = run_content_discovery('https://example.com', mock_fn, 'shallow')
        _assert_standard_format(result, 'content_discovery')


class TestParamDiscovery:
    def test_standard_format(self):
        from apps.scanning.engine.recon.param_discovery import run_param_discovery
        mock_fn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html>ok</html>'
        mock_resp.headers = {'Content-Length': '14'}
        mock_fn.return_value = mock_resp
        result = run_param_discovery('https://example.com', mock_fn, 'shallow')
        _assert_standard_format(result, 'param_discovery')


class TestAPIDiscovery:
    def test_standard_format(self):
        from apps.scanning.engine.recon.api_discovery import run_api_discovery
        mock_fn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.headers = {}
        mock_resp.text = ''
        mock_fn.return_value = mock_resp
        result = run_api_discovery('https://example.com', mock_fn, 'shallow')
        _assert_standard_format(result, 'api_discovery')


# ---------------------------------------------------------------------------
# P2 new modules
# ---------------------------------------------------------------------------
class TestSubdomainBrute:
    def test_standard_format(self):
        from apps.scanning.engine.recon.subdomain_brute import run_subdomain_brute
        with patch('socket.getaddrinfo', side_effect=OSError):
            result = run_subdomain_brute('https://example.com', depth='quick')
        _assert_standard_format(result, 'subdomain_brute')


class TestEmailEnum:
    def test_standard_format(self):
        from apps.scanning.engine.recon.email_enum import run_email_enum
        result = run_email_enum(
            target_url='https://example.com',
            response_body='<html>contact: admin@example.com</html>',
        )
        _assert_standard_format(result, 'email_enum')


class TestSocialRecon:
    def test_standard_format(self):
        from apps.scanning.engine.recon.social_recon import run_social_recon
        result = run_social_recon(
            target_url='https://example.com',
            response_body='<a href="https://twitter.com/example">twitter</a>',
        )
        _assert_standard_format(result, 'social_recon')


class TestCMSFingerprint:
    def test_standard_format(self):
        from apps.scanning.engine.recon.cms_fingerprint import run_cms_fingerprint
        result = run_cms_fingerprint(
            target_url='https://example.com',
            response_body='<meta name="generator" content="WordPress 6.4">',
            response_headers={'X-Powered-By': 'PHP/8.1'},
        )
        _assert_standard_format(result, 'cms_fingerprint')


class TestNetworkMapper:
    def test_standard_format(self):
        from apps.scanning.engine.recon.network_mapper import run_network_mapper
        result = run_network_mapper(
            target_url='https://example.com',
            dns_results={'hostname': 'example.com', 'ip_addresses': ['93.184.216.34']},
        )
        _assert_standard_format(result, 'network_mapper')


# ---------------------------------------------------------------------------
# P3 new modules
# ---------------------------------------------------------------------------
class TestVulnCorrelator:
    def test_standard_format(self):
        from apps.scanning.engine.recon.vuln_correlator import run_vuln_correlator
        result = run_vuln_correlator('https://example.com', recon_data={
            'technologies': {'technologies': [{'name': 'WordPress', 'version': '5.0'}]},
        })
        _assert_standard_format(result, 'vuln_correlator')


class TestAttackSurface:
    def test_standard_format(self):
        from apps.scanning.engine.recon.attack_surface import run_attack_surface
        result = run_attack_surface('https://example.com', recon_data={})
        _assert_standard_format(result, 'attack_surface')


class TestThreatIntel:
    def test_standard_format(self):
        from apps.scanning.engine.recon.threat_intel import run_threat_intel
        result = run_threat_intel('https://example.com', recon_data={
            'dns': {'hostname': 'example.com', 'ip_addresses': ['93.184.216.34']},
        })
        _assert_standard_format(result, 'threat_intel')


class TestRiskScorer:
    def test_standard_format(self):
        from apps.scanning.engine.recon.risk_scorer import run_risk_scorer
        result = run_risk_scorer('https://example.com', recon_data={})
        _assert_standard_format(result, 'risk_scorer')
        # Should have grade
        assert 'grade' in result or 'overall_score' in result


# ---------------------------------------------------------------------------
# __init__.py import tests
# ---------------------------------------------------------------------------
class TestReconInit:
    def test_all_exports(self):
        """All 25 module functions should be importable from the recon package."""
        from apps.scanning.engine.recon import (
            run_dns_recon, run_whois_recon, run_port_scan,
            run_tech_fingerprint, run_waf_detection, run_cert_analysis,
            run_header_analysis, run_cookie_analysis, run_ai_recon,
            run_ct_log_enum, run_subdomain_enum, run_url_harvester, run_js_analyzer,
            run_cloud_detect, run_cors_analyzer, run_content_discovery,
            run_param_discovery, run_api_discovery,
            run_subdomain_brute, run_email_enum, run_social_recon,
            run_cms_fingerprint, run_network_mapper,
            run_vuln_correlator, run_attack_surface, run_threat_intel, run_risk_scorer,
        )
        # All should be callable
        for fn in [
            run_dns_recon, run_whois_recon, run_port_scan,
            run_tech_fingerprint, run_waf_detection, run_cert_analysis,
            run_header_analysis, run_cookie_analysis, run_ai_recon,
            run_ct_log_enum, run_subdomain_enum, run_url_harvester, run_js_analyzer,
            run_cloud_detect, run_cors_analyzer, run_content_discovery,
            run_param_discovery, run_api_discovery,
            run_subdomain_brute, run_email_enum, run_social_recon,
            run_cms_fingerprint, run_network_mapper,
            run_vuln_correlator, run_attack_surface, run_threat_intel, run_risk_scorer,
        ]:
            assert callable(fn), f'{fn} is not callable'
