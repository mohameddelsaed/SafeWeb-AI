"""
Tests for Phase 23 — OSINT & External Intelligence Integration.

All external API calls are mocked.
"""
from unittest.mock import patch, MagicMock


# ────────────────────────────────────────────────────────────────────────────
#  Shodan Intel
# ────────────────────────────────────────────────────────────────────────────

class TestShodanIntel:
    """Tests for shodan_intel module."""

    @patch('apps.scanning.engine.osint.shodan_intel._get_api_key', return_value='')
    def test_returns_none_without_api_key(self, mock_key):
        from apps.scanning.engine.osint.shodan_intel import run_shodan_intel
        result = run_shodan_intel('https://example.com')
        assert result is None

    @patch('apps.scanning.engine.osint.shodan_intel.requests.get')
    @patch('apps.scanning.engine.osint.shodan_intel._get_api_key', return_value='test-key')
    def test_host_query_success(self, mock_key, mock_get):
        from apps.scanning.engine.osint.shodan_intel import run_shodan_intel

        host_resp = MagicMock()
        host_resp.status_code = 200
        host_resp.json.return_value = {
            'org': 'TestOrg',
            'isp': 'TestISP',
            'asn': 'AS12345',
            'os': 'Linux',
            'ports': [80, 443],
            'hostnames': ['example.com'],
            'country_code': 'US',
            'city': 'NYC',
            'vulns': ['CVE-2021-1234'],
            'data': [
                {
                    'port': 80,
                    'transport': 'tcp',
                    'product': 'nginx',
                    'version': '1.19',
                    'data': 'HTTP/1.1 200 OK',
                },
                {
                    'port': 443,
                    'transport': 'tcp',
                    'product': 'nginx',
                    'data': '',
                    'ssl': {
                        'cert': {
                            'issuer': {'CN': 'LetsEncrypt'},
                            'expires': '2025-01-01',
                        },
                        'cipher': {'name': 'TLS_AES_256'},
                    },
                },
            ],
        }
        dns_resp = MagicMock()
        dns_resp.status_code = 200
        dns_resp.json.return_value = {'example.com': '1.2.3.4'}

        mock_get.side_effect = [host_resp, dns_resp]

        result = run_shodan_intel('https://example.com', ip_addresses=['1.2.3.4'])
        assert result is not None
        assert result['module'] == 'shodan_intel'
        assert len(result['hosts']) == 1
        assert result['hosts'][0]['org'] == 'TestOrg'
        assert 80 in result['ports']
        assert 443 in result['ports']
        assert 'CVE-2021-1234' in result['vulns']
        assert result['stats']['hosts_found'] == 1

        # Check findings
        vuln_findings = [f for f in result['findings'] if f['type'] == 'known_vulnerability']
        assert len(vuln_findings) == 1
        assert vuln_findings[0]['cve'] == 'CVE-2021-1234'

        svc_findings = [f for f in result['findings'] if f['type'] == 'exposed_service']
        assert len(svc_findings) == 2

        ssl_entries = result['ssl_info']
        assert len(ssl_entries) == 1
        assert ssl_entries[0]['port'] == 443

    @patch('apps.scanning.engine.osint.shodan_intel.requests.get')
    @patch('apps.scanning.engine.osint.shodan_intel._get_api_key', return_value='test-key')
    def test_host_query_error_handling(self, mock_key, mock_get):
        from apps.scanning.engine.osint.shodan_intel import run_shodan_intel

        error_resp = MagicMock()
        error_resp.status_code = 401

        dns_resp = MagicMock()
        dns_resp.status_code = 200
        dns_resp.json.return_value = {}

        mock_get.side_effect = [error_resp, dns_resp]

        result = run_shodan_intel('https://example.com', ip_addresses=['1.2.3.4'])
        assert result is not None
        assert any('Invalid' in e for e in result['errors'])

    @patch('apps.scanning.engine.osint.shodan_intel.requests.get')
    @patch('apps.scanning.engine.osint.shodan_intel._get_api_key', return_value='test-key')
    def test_request_exception(self, mock_key, mock_get):
        from apps.scanning.engine.osint.shodan_intel import run_shodan_intel
        import requests as req_lib
        mock_get.side_effect = req_lib.ConnectionError('timeout')
        result = run_shodan_intel('https://example.com', ip_addresses=['1.2.3.4'])
        assert result is not None
        assert len(result['errors']) > 0


# ────────────────────────────────────────────────────────────────────────────
#  Censys Intel
# ────────────────────────────────────────────────────────────────────────────

class TestCensysIntel:
    """Tests for censys_intel module."""

    @patch('apps.scanning.engine.osint.censys_intel._get_credentials', return_value=('', ''))
    def test_returns_none_without_credentials(self, mock_creds):
        from apps.scanning.engine.osint.censys_intel import run_censys_intel
        result = run_censys_intel('https://example.com')
        assert result is None

    @patch('apps.scanning.engine.osint.censys_intel.requests.get')
    @patch('apps.scanning.engine.osint.censys_intel._get_credentials',
           return_value=('test-id', 'test-secret'))
    def test_certificate_and_host_search(self, mock_creds, mock_get):
        from apps.scanning.engine.osint.censys_intel import run_censys_intel

        cert_resp = MagicMock()
        cert_resp.status_code = 200
        cert_resp.json.return_value = {
            'result': {
                'hits': [
                    {
                        'fingerprint_sha256': 'abc123def456',
                        'parsed': {
                            'issuer_dn': 'CN=LetsEncrypt',
                            'subject_dn': 'CN=example.com',
                            'validity': {'start': '2024-01-01', 'end': '2025-01-01'},
                        },
                        'names': ['example.com', '*.example.com', 'sub.example.com'],
                    }
                ]
            }
        }

        host_resp = MagicMock()
        host_resp.status_code = 200
        host_resp.json.return_value = {
            'result': {
                'hits': [
                    {
                        'ip': '1.2.3.4',
                        'services': [
                            {'port': 443, 'service_name': 'HTTPS', 'transport_protocol': 'TCP'},
                        ],
                        'autonomous_system': {'asn': 12345},
                        'location': {'country': 'US'},
                    }
                ]
            }
        }

        mock_get.side_effect = [cert_resp, host_resp]

        result = run_censys_intel('https://example.com')
        assert result is not None
        assert result['module'] == 'censys_intel'
        assert len(result['certificates']) == 1
        assert len(result['hosts']) == 1
        assert 'sub.example.com' in result['related_domains']
        assert result['stats']['certs_found'] == 1
        assert result['stats']['hosts_found'] == 1
        assert result['stats']['queries'] == 2

        domain_findings = [f for f in result['findings'] if f['type'] == 'related_domain']
        assert len(domain_findings) >= 1

        host_findings = [f for f in result['findings'] if f['type'] == 'discovered_host']
        assert len(host_findings) == 1

    @patch('apps.scanning.engine.osint.censys_intel.requests.get')
    @patch('apps.scanning.engine.osint.censys_intel._get_credentials',
           return_value=('test-id', 'test-secret'))
    def test_rate_limit_error(self, mock_creds, mock_get):
        from apps.scanning.engine.osint.censys_intel import run_censys_intel

        resp = MagicMock()
        resp.status_code = 429
        mock_get.return_value = resp

        result = run_censys_intel('https://example.com')
        assert result is not None
        assert any('rate limit' in e for e in result['errors'])


# ────────────────────────────────────────────────────────────────────────────
#  Wayback Machine Intel
# ────────────────────────────────────────────────────────────────────────────

class TestWaybackIntel:
    """Tests for wayback_intel module."""

    @patch('apps.scanning.engine.osint.wayback_intel.requests.get')
    def test_url_discovery(self, mock_get):
        from apps.scanning.engine.osint.wayback_intel import run_wayback_intel

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [
            ['original', 'statuscode', 'mimetype', 'timestamp'],
            ['https://example.com/admin/login', '200', 'text/html', '20230101'],
            ['https://example.com/api/v1/users', '200', 'application/json', '20230201'],
            ['https://example.com/backup.sql', '200', 'application/octet-stream', '20220601'],
            ['https://example.com/page?id=1&sort=asc', '200', 'text/html', '20230301'],
        ]
        mock_get.return_value = resp

        result = run_wayback_intel('https://example.com')
        assert result is not None
        assert result['module'] == 'wayback_intel'
        assert result['stats']['urls_found'] == 4
        assert len(result['urls']) == 4

        # Check interesting files detected
        file_findings = [f for f in result['findings'] if f['type'] == 'interesting_file']
        assert len(file_findings) >= 1  # backup.sql

        # Check interesting paths detected
        path_findings = [f for f in result['findings'] if f['type'] == 'interesting_path']
        assert len(path_findings) >= 1  # /admin, /api

        # Check parameter extraction
        params = {p['name'] for p in result['parameters']}
        assert 'id' in params
        assert 'sort' in params

    @patch('apps.scanning.engine.osint.wayback_intel.requests.get')
    def test_empty_cdx_result(self, mock_get):
        from apps.scanning.engine.osint.wayback_intel import run_wayback_intel

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = [
            ['original', 'statuscode', 'mimetype', 'timestamp'],
        ]
        mock_get.return_value = resp

        result = run_wayback_intel('https://example.com')
        assert result is not None
        assert result['stats']['urls_found'] == 0
        assert len(result['findings']) == 0

    @patch('apps.scanning.engine.osint.wayback_intel.requests.get')
    def test_request_failure(self, mock_get):
        from apps.scanning.engine.osint.wayback_intel import run_wayback_intel
        import requests as req_lib
        mock_get.side_effect = req_lib.ConnectionError('timeout')
        result = run_wayback_intel('https://example.com')
        assert result is not None
        assert len(result['errors']) > 0

    def test_no_api_key_needed(self):
        """Wayback should always return a result (no API key required)."""
        from apps.scanning.engine.osint.wayback_intel import run_wayback_intel
        with patch('apps.scanning.engine.osint.wayback_intel.requests.get') as mock_get:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = [['original', 'statuscode', 'mimetype', 'timestamp']]
            mock_get.return_value = resp
            result = run_wayback_intel('https://example.com')
            assert result is not None  # Never None — no API key gating


# ────────────────────────────────────────────────────────────────────────────
#  GitHub Intel
# ────────────────────────────────────────────────────────────────────────────

class TestGithubIntel:
    """Tests for github_intel module."""

    @patch('apps.scanning.engine.osint.github_intel._get_token', return_value='')
    def test_returns_none_without_token(self, mock_tok):
        from apps.scanning.engine.osint.github_intel import run_github_intel
        result = run_github_intel('https://example.com')
        assert result is None

    @patch('apps.scanning.engine.osint.github_intel.requests.get')
    @patch('apps.scanning.engine.osint.github_intel._get_token', return_value='ghp_test123')
    def test_code_search_success(self, mock_tok, mock_get):
        from apps.scanning.engine.osint.github_intel import run_github_intel

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            'total_count': 2,
            'items': [
                {
                    'name': '.env',
                    'path': 'config/.env',
                    'html_url': 'https://github.com/org/repo/blob/main/.env',
                    'score': 10.5,
                    'repository': {
                        'full_name': 'org/repo',
                        'private': False,
                        'description': 'Test repo',
                    },
                    'text_matches': [
                        {'fragment': 'API_KEY=sk-abc123secret'},
                    ],
                },
                {
                    'name': 'config.py',
                    'path': 'src/config.py',
                    'html_url': 'https://github.com/org2/repo2/blob/main/config.py',
                    'score': 8.0,
                    'repository': {
                        'full_name': 'org2/repo2',
                        'private': False,
                        'description': '',
                    },
                    'text_matches': [],
                },
            ],
        }
        mock_get.return_value = resp

        result = run_github_intel('https://example.com')
        assert result is not None
        assert result['module'] == 'github_intel'
        assert result['stats']['results_found'] == 2
        assert len(result['code_results']) == 2
        assert len(result['repos']) == 2

        # .env file should be flagged as sensitive
        sensitive = [f for f in result['findings'] if f['type'] == 'sensitive_file']
        assert len(sensitive) >= 1

        # API key leak should be detected from text_matches
        leaks = [f for f in result['findings'] if f['type'] in ('api_key_leak', 'secret_leak')]
        assert len(leaks) >= 1
        assert result['stats']['leaks_found'] >= 1

    @patch('apps.scanning.engine.osint.github_intel.requests.get')
    @patch('apps.scanning.engine.osint.github_intel._get_token', return_value='ghp_test123')
    def test_auth_error(self, mock_tok, mock_get):
        from apps.scanning.engine.osint.github_intel import run_github_intel
        resp = MagicMock()
        resp.status_code = 401
        mock_get.return_value = resp
        result = run_github_intel('https://example.com')
        assert any('Invalid' in e for e in result['errors'])


# ────────────────────────────────────────────────────────────────────────────
#  VirusTotal Intel
# ────────────────────────────────────────────────────────────────────────────

class TestVTIntel:
    """Tests for vt_intel module."""

    @patch('apps.scanning.engine.osint.vt_intel._get_api_key', return_value='')
    def test_returns_none_without_api_key(self, mock_key):
        from apps.scanning.engine.osint.vt_intel import run_vt_intel
        result = run_vt_intel('https://example.com')
        assert result is None

    @patch('apps.scanning.engine.osint.vt_intel.requests.get')
    @patch('apps.scanning.engine.osint.vt_intel._get_api_key', return_value='vt-test-key')
    def test_full_domain_intelligence(self, mock_key, mock_get):
        from apps.scanning.engine.osint.vt_intel import run_vt_intel

        domain_resp = MagicMock()
        domain_resp.status_code = 200
        domain_resp.json.return_value = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 2,
                        'suspicious': 1,
                        'harmless': 50,
                        'undetected': 10,
                    },
                    'categories': {'Forcepoint': 'technology'},
                    'registrar': 'GoDaddy',
                    'creation_date': 1609459200,
                    'reputation': 5,
                },
            },
        }

        subdomain_resp = MagicMock()
        subdomain_resp.status_code = 200
        subdomain_resp.json.return_value = {
            'data': [
                {'id': 'api.example.com'},
                {'id': 'mail.example.com'},
            ],
        }

        dns_resp = MagicMock()
        dns_resp.status_code = 200
        dns_resp.json.return_value = {
            'data': [
                {
                    'attributes': {
                        'ip_address': '1.2.3.4',
                        'date': 1640000000,
                        'host_name_last_analysis_stats': {},
                    },
                },
            ],
        }

        mock_get.side_effect = [domain_resp, subdomain_resp, dns_resp]

        result = run_vt_intel('https://example.com')
        assert result is not None
        assert result['module'] == 'vt_intel'
        assert result['reputation']['malicious'] == 2
        assert result['reputation']['suspicious'] == 1
        assert result['stats']['subdomains_found'] == 2
        assert 'api.example.com' in result['subdomains']
        assert result['stats']['queries'] == 3

        # Malicious finding
        mal_findings = [f for f in result['findings'] if f['type'] == 'malicious_domain']
        assert len(mal_findings) == 1

        # Suspicious finding
        sus_findings = [f for f in result['findings'] if f['type'] == 'suspicious_domain']
        assert len(sus_findings) == 1

        # Subdomain findings
        sub_findings = [f for f in result['findings'] if f['type'] == 'subdomain']
        assert len(sub_findings) == 2

        # Passive DNS findings
        dns_findings = [f for f in result['findings'] if f['type'] == 'passive_dns']
        assert len(dns_findings) == 1

    @patch('apps.scanning.engine.osint.vt_intel.requests.get')
    @patch('apps.scanning.engine.osint.vt_intel._get_api_key', return_value='vt-test-key')
    def test_rate_limit_handling(self, mock_key, mock_get):
        from apps.scanning.engine.osint.vt_intel import run_vt_intel

        resp = MagicMock()
        resp.status_code = 429
        mock_get.return_value = resp

        result = run_vt_intel('https://example.com')
        assert result is not None
        assert any('rate limit' in e for e in result['errors'])


# ────────────────────────────────────────────────────────────────────────────
#  Integration: Graceful Degradation
# ────────────────────────────────────────────────────────────────────────────

class TestOSINTIntegration:
    """Integration-level tests for OSINT graceful degradation."""

    def test_all_modules_importable(self):
        """Verify all OSINT modules can be imported."""
        from apps.scanning.engine.osint.shodan_intel import run_shodan_intel
        from apps.scanning.engine.osint.censys_intel import run_censys_intel
        from apps.scanning.engine.osint.wayback_intel import run_wayback_intel
        from apps.scanning.engine.osint.github_intel import run_github_intel
        from apps.scanning.engine.osint.vt_intel import run_vt_intel
        assert callable(run_shodan_intel)
        assert callable(run_censys_intel)
        assert callable(run_wayback_intel)
        assert callable(run_github_intel)
        assert callable(run_vt_intel)

    @patch.dict('os.environ', {}, clear=False)
    def test_graceful_degradation_no_keys(self):
        """All API-gated modules return None when no keys configured."""
        with patch('apps.scanning.engine.osint.shodan_intel._get_api_key', return_value=''):
            from apps.scanning.engine.osint.shodan_intel import run_shodan_intel
            assert run_shodan_intel('https://example.com') is None

        with patch('apps.scanning.engine.osint.censys_intel._get_credentials', return_value=('', '')):
            from apps.scanning.engine.osint.censys_intel import run_censys_intel
            assert run_censys_intel('https://example.com') is None

        with patch('apps.scanning.engine.osint.github_intel._get_token', return_value=''):
            from apps.scanning.engine.osint.github_intel import run_github_intel
            assert run_github_intel('https://example.com') is None

        with patch('apps.scanning.engine.osint.vt_intel._get_api_key', return_value=''):
            from apps.scanning.engine.osint.vt_intel import run_vt_intel
            assert run_vt_intel('https://example.com') is None

    def test_settings_keys_defined(self):
        """Verify Django settings have the OSINT API key entries."""
        from django.conf import settings
        assert hasattr(settings, 'SHODAN_API_KEY')
        assert hasattr(settings, 'CENSYS_API_ID')
        assert hasattr(settings, 'CENSYS_API_SECRET')
        assert hasattr(settings, 'VT_API_KEY')
        assert hasattr(settings, 'GITHUB_TOKEN')
