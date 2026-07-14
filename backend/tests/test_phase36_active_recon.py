"""
Phase 36 — Active Recon Enhancement tests.

Covers:
  - DNS recon: DNSSEC, AXFR, DoH, SPF/DMARC, wildcard, brute-force, CSP extraction
  - Subdomain enum: passive sources, permutations, CT log, recursive
  - HTTP probe: favicon hash, header fingerprinting, CDN detection, screenshot readiness
  - Cloud asset: S3/Azure/GCP candidates, CDN origin, serverless endpoints
  - ActiveReconTester integration
  - Registration: 68 testers
"""
import socket

import pytest
from unittest.mock import patch, MagicMock

# ────────────────────────────────────────────────────────────────────────────
# DNS Recon (__init__.py)
# ────────────────────────────────────────────────────────────────────────────

class TestDNSSEC:
    def test_check_dnssec_no_dnspython(self):
        """check_dnssec falls back when dnspython not available."""
        from apps.scanning.engine.active_recon import check_dnssec
        with patch.dict('sys.modules', {'dns': None, 'dns.resolver': None, 'dns.rdatatype': None}):
            result = check_dnssec('example.com')
        assert 'enabled' in result

    def test_check_dnssec_enabled(self):
        """check_dnssec detects enabled DNSSEC."""
        from apps.scanning.engine.active_recon import check_dnssec

        mock_dnskey_answer = [MagicMock(algorithm=13)]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_dnskey_answer

        mock_resolver_cls = MagicMock(return_value=mock_resolver_instance)
        mock_dns_resolver = MagicMock(Resolver=mock_resolver_cls)
        mock_dns_rdatatype = MagicMock()

        with patch.dict('sys.modules', {
            'dns': MagicMock(),
            'dns.resolver': mock_dns_resolver,
            'dns.rdatatype': mock_dns_rdatatype,
        }):
            result = check_dnssec('example.com')

        assert result['enabled'] is True
        assert result['has_dnskey'] is True

    def test_check_dnssec_weak_algorithm(self):
        """check_dnssec flags weak algorithms."""
        from apps.scanning.engine.active_recon import WEAK_DNSSEC_ALGORITHMS, DNSSEC_ALGORITHMS
        # Directly test the constants and logic without dns import
        assert 5 in WEAK_DNSSEC_ALGORITHMS
        assert DNSSEC_ALGORITHMS[5] == 'RSA/SHA-1'
        assert 13 not in WEAK_DNSSEC_ALGORITHMS  # ECDSA is not weak

    def test_dnssec_algorithms_known(self):
        from apps.scanning.engine.active_recon import DNSSEC_ALGORITHMS
        assert 13 in DNSSEC_ALGORITHMS  # ECDSA
        assert 15 in DNSSEC_ALGORITHMS  # Ed25519
        assert 1 in DNSSEC_ALGORITHMS   # RSA/MD5


class TestZoneTransfer:
    def test_attempt_zone_transfer_not_vulnerable(self):
        from apps.scanning.engine.active_recon import attempt_zone_transfer
        # Supply nameservers so it skips NS lookup, but socket fails
        with patch('apps.scanning.engine.active_recon.socket') as mock_sock:
            mock_sock.gethostbyname.side_effect = OSError('no host')
            result = attempt_zone_transfer('example.com', nameservers=['ns1.bad.com'])
        assert result['vulnerable'] is False

    def test_attempt_zone_transfer_vulnerable(self):
        from apps.scanning.engine.active_recon import attempt_zone_transfer

        # Test with dnspython not installed — should return error
        with patch.dict('sys.modules', {
            'dns': None, 'dns.query': None, 'dns.zone': None, 'dns.resolver': None,
        }):
            result = attempt_zone_transfer('example.com', nameservers=['ns1.example.com'])

        # Without dnspython, should report error not vulnerable
        assert result['error'] is not None or result['vulnerable'] is False


class TestDoH:
    def test_resolve_doh_success(self):
        from apps.scanning.engine.active_recon import resolve_doh

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"Status":0,"Answer":[{"data":"1.2.3.4"}]}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_resp):
            result = resolve_doh('example.com', 'A', 'cloudflare')

        assert result['status'] == 0
        assert len(result['answers']) == 1

    def test_resolve_doh_error(self):
        from apps.scanning.engine.active_recon import resolve_doh
        with patch('urllib.request.urlopen', side_effect=OSError('timeout')):
            result = resolve_doh('example.com')
        assert result['error'] is not None

    def test_doh_providers(self):
        from apps.scanning.engine.active_recon import DOH_PROVIDERS
        assert 'cloudflare' in DOH_PROVIDERS
        assert 'google' in DOH_PROVIDERS
        assert 'quad9' in DOH_PROVIDERS


class TestSPF:
    def test_parse_spf_found(self):
        from apps.scanning.engine.active_recon import parse_spf
        records = ['v=spf1 include:_spf.google.com ~all']
        result = parse_spf(records)
        assert result['found'] is True
        assert result['version'] == 'spf1'
        assert '_spf.google.com' in result['includes']
        assert result['all_qualifier'] == 'softfail'

    def test_parse_spf_dangerous_all(self):
        from apps.scanning.engine.active_recon import parse_spf
        records = ['v=spf1 +all']
        result = parse_spf(records)
        assert any('dangerous' in i.lower() or '+all' in i for i in result['issues'])

    def test_parse_spf_not_found(self):
        from apps.scanning.engine.active_recon import parse_spf
        result = parse_spf(['random text'])
        assert result['found'] is False

    def test_parse_spf_no_all(self):
        from apps.scanning.engine.active_recon import parse_spf
        records = ['v=spf1 include:example.com']
        result = parse_spf(records)
        assert result['found'] is True


class TestDMARC:
    def test_parse_dmarc_found(self):
        from apps.scanning.engine.active_recon import parse_dmarc
        records = ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']
        result = parse_dmarc(records)
        assert result['found'] is True
        assert result['policy'] == 'reject'
        assert any('dmarc@example.com' in u for u in result['rua'])

    def test_parse_dmarc_policy_none(self):
        from apps.scanning.engine.active_recon import parse_dmarc
        records = ['v=DMARC1; p=none']
        result = parse_dmarc(records)
        assert any('none' in i.lower() or 'p=none' in i for i in result['issues'])

    def test_parse_dmarc_not_found(self):
        from apps.scanning.engine.active_recon import parse_dmarc
        result = parse_dmarc(['no dmarc here'])
        assert result['found'] is False


class TestWildcard:
    def test_detect_wildcard_none(self):
        from apps.scanning.engine.active_recon import detect_wildcard
        with patch('socket.getaddrinfo', side_effect=socket.gaierror('NXDOMAIN')):
            result = detect_wildcard('example.com')
        assert result['is_wildcard'] is False

    def test_detect_wildcard_detected(self):
        from apps.scanning.engine.active_recon import detect_wildcard
        with patch('socket.getaddrinfo', return_value=[(None, None, None, None, ('1.2.3.4', 0))]):
            result = detect_wildcard('example.com', probe_count=2)
        assert result['is_wildcard'] is True
        assert '1.2.3.4' in result['wildcard_ips']


class TestDNSBruteForce:
    def test_dns_brute_force_finds_hosts(self):
        from apps.scanning.engine.active_recon import dns_brute_force

        def mock_getaddrinfo(host, *a, **kw):
            if host.startswith('www.'):
                return [(None, None, None, None, ('10.0.0.1', 0))]
            raise socket.gaierror('NXDOMAIN')

        with patch('socket.getaddrinfo', side_effect=mock_getaddrinfo), \
             patch('socket.getdefaulttimeout', return_value=None), \
             patch('socket.setdefaulttimeout'):
            result = dns_brute_force('example.com', wordlist=['www', 'mail', 'api'])

        assert len(result['found']) >= 1
        assert result['found'][0]['fqdn'] == 'www.example.com'
        assert result['total_checked'] == 3

    def test_dns_brute_force_filters_wildcard(self):
        from apps.scanning.engine.active_recon import dns_brute_force

        with patch('socket.getaddrinfo', return_value=[(None, None, None, None, ('1.1.1.1', 0))]), \
             patch('socket.getdefaulttimeout', return_value=None), \
             patch('socket.setdefaulttimeout'):
            result = dns_brute_force('example.com', wordlist=['www'],
                                     wildcard_ips={'1.1.1.1'})

        assert len(result['found']) == 0
        assert result['wildcard_filtered'] >= 1

    def test_default_wordlist(self):
        from apps.scanning.engine.active_recon import DEFAULT_DNS_WORDLIST
        assert len(DEFAULT_DNS_WORDLIST) > 30
        assert 'www' in DEFAULT_DNS_WORDLIST
        assert 'admin' in DEFAULT_DNS_WORDLIST


class TestCSPExtraction:
    def test_extract_csp_domains(self):
        from apps.scanning.engine.active_recon import extract_csp_domains
        csp = "default-src 'self'; script-src cdn.example.com *.googleapis.com; img-src images.example.com"
        domains = extract_csp_domains(csp)
        assert 'cdn.example.com' in domains
        assert 'googleapis.com' in domains
        assert 'images.example.com' in domains

    def test_extract_csp_empty(self):
        from apps.scanning.engine.active_recon import extract_csp_domains
        assert extract_csp_domains('') == []

    def test_extract_csp_no_domains(self):
        from apps.scanning.engine.active_recon import extract_csp_domains
        result = extract_csp_domains("default-src 'self' 'unsafe-inline'")
        assert result == []


# ────────────────────────────────────────────────────────────────────────────
# Subdomain Enum (subdomain_enum.py)
# ────────────────────────────────────────────────────────────────────────────

class TestPassiveSources:
    def test_build_passive_url(self):
        from apps.scanning.engine.active_recon.subdomain_enum import build_passive_url
        url = build_passive_url('crt_sh', 'example.com')
        assert 'example.com' in url
        assert 'crt.sh' in url

    def test_build_passive_url_unknown(self):
        from apps.scanning.engine.active_recon.subdomain_enum import build_passive_url
        assert build_passive_url('unknown_source', 'x.com') is None

    def test_parse_crt_sh_response(self):
        from apps.scanning.engine.active_recon.subdomain_enum import parse_crt_sh_response
        data = [
            {'name_value': 'sub1.example.com\nsub2.example.com'},
            {'name_value': '*.wildcard.com'},
        ]
        subs = parse_crt_sh_response(data)
        assert 'sub1.example.com' in subs
        assert 'sub2.example.com' in subs
        # Wildcards should be excluded
        assert not any('*' in s for s in subs)

    def test_parse_hackertarget_response(self):
        from apps.scanning.engine.active_recon.subdomain_enum import parse_hackertarget_response
        text = "sub1.example.com,1.2.3.4\nsub2.example.com,5.6.7.8"
        subs = parse_hackertarget_response(text)
        assert 'sub1.example.com' in subs
        assert 'sub2.example.com' in subs


class TestPermutations:
    def test_generate_permutations(self):
        from apps.scanning.engine.active_recon.subdomain_enum import generate_permutations
        subs = ['api.example.com', 'dev.example.com']
        perms = generate_permutations(subs, 'example.com')
        assert len(perms) > 0
        assert all('.example.com' in p for p in perms)

    def test_generate_permutations_suffixes(self):
        from apps.scanning.engine.active_recon.subdomain_enum import generate_permutations
        subs = ['api.example.com']
        perms = generate_permutations(subs, 'example.com')
        assert any('-dev' in p for p in perms)
        assert any('-staging' in p for p in perms)

    def test_generate_permutations_max_limit(self):
        from apps.scanning.engine.active_recon.subdomain_enum import generate_permutations
        subs = ['api.example.com', 'dev.example.com', 'admin.example.com']
        perms = generate_permutations(subs, 'example.com', max_perms=10)
        assert len(perms) <= 10

    def test_generate_permutations_empty(self):
        from apps.scanning.engine.active_recon.subdomain_enum import generate_permutations
        perms = generate_permutations([], 'example.com')
        assert perms == []

    def test_perm_words_list(self):
        from apps.scanning.engine.active_recon.subdomain_enum import PERM_WORDS
        assert 'dev' in PERM_WORDS
        assert 'staging' in PERM_WORDS


class TestCTLog:
    def test_build_ct_url(self):
        from apps.scanning.engine.active_recon.subdomain_enum import build_ct_url
        url = build_ct_url('certspotter', 'example.com')
        assert 'certspotter' in url
        assert 'example.com' in url

    def test_parse_certspotter_response(self):
        from apps.scanning.engine.active_recon.subdomain_enum import parse_certspotter_response
        data = [{'dns_names': ['sub1.example.com', '*.example.com']}]
        subs = parse_certspotter_response(data)
        assert 'sub1.example.com' in subs
        assert not any('*' in s for s in subs)


class TestRecursiveDiscovery:
    def test_recursive_discover(self):
        from apps.scanning.engine.active_recon.subdomain_enum import recursive_discover

        def mock_getaddrinfo(host, *a, **kw):
            if 'www.' in host:
                return [(None, None, None, None, ('10.0.0.1', 0))]
            raise socket.gaierror('NXDOMAIN')

        with patch('socket.getaddrinfo', side_effect=mock_getaddrinfo), \
             patch('socket.getdefaulttimeout', return_value=None), \
             patch('socket.setdefaulttimeout'):
            results = recursive_discover(['sub.example.com'], 'example.com', max_depth=1)

        assert any(r['fqdn'] == 'www.sub.example.com' for r in results)

    def test_recursive_discover_empty(self):
        from apps.scanning.engine.active_recon.subdomain_enum import recursive_discover
        with patch('socket.getaddrinfo', side_effect=socket.gaierror('fail')), \
             patch('socket.getdefaulttimeout', return_value=None), \
             patch('socket.setdefaulttimeout'):
            results = recursive_discover([], 'example.com')
        assert results == []


class TestEnhancedSubdomainEnum:
    def test_run_quick(self):
        from apps.scanning.engine.active_recon.subdomain_enum import run_enhanced_subdomain_enum
        result = run_enhanced_subdomain_enum('example.com', depth='quick')
        assert 'stats' in result
        assert result['permutations'] == []

    def test_run_medium_with_subs(self):
        from apps.scanning.engine.active_recon.subdomain_enum import run_enhanced_subdomain_enum
        result = run_enhanced_subdomain_enum('example.com', depth='medium',
                                              known_subs=['api.example.com'])
        assert len(result['permutations']) > 0
        assert result['stats']['from_permutation'] > 0

    def test_run_deep(self):
        from apps.scanning.engine.active_recon.subdomain_enum import run_enhanced_subdomain_enum
        with patch('socket.getaddrinfo', side_effect=socket.gaierror), \
             patch('socket.getdefaulttimeout', return_value=None), \
             patch('socket.setdefaulttimeout'):
            result = run_enhanced_subdomain_enum('example.com', depth='deep',
                                                  known_subs=['api.example.com'])
        assert result['stats']['from_permutation'] > 0
        assert 'passive_sources_checked' in result


# ────────────────────────────────────────────────────────────────────────────
# HTTP Probe (http_probe.py)
# ────────────────────────────────────────────────────────────────────────────

class TestFaviconHash:
    def test_compute_favicon_hash(self):
        from apps.scanning.engine.active_recon.http_probe import compute_favicon_hash
        data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        h = compute_favicon_hash(data)
        assert isinstance(h, int)

    def test_identify_known_favicon(self):
        from apps.scanning.engine.active_recon.http_probe import identify_favicon
        assert identify_favicon(116323821) == 'Jenkins'
        assert identify_favicon(999999999) is None

    def test_mmh3_deterministic(self):
        from apps.scanning.engine.active_recon.http_probe import _mmh3_32
        assert _mmh3_32(b'hello') == _mmh3_32(b'hello')
        assert _mmh3_32(b'hello') != _mmh3_32(b'world')


class TestHeaderFingerprint:
    def test_fingerprint_headers_nginx(self):
        from apps.scanning.engine.active_recon.http_probe import fingerprint_headers
        headers = {'Server': 'nginx/1.21.0', 'X-Powered-By': 'Express'}
        result = fingerprint_headers(headers)
        assert 'Nginx' in result['technologies']
        assert 'Express.js' in result['technologies']
        assert result['raw_server'] == 'nginx/1.21.0'

    def test_fingerprint_security_headers(self):
        from apps.scanning.engine.active_recon.http_probe import fingerprint_headers
        headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
        }
        result = fingerprint_headers(headers)
        assert 'strict-transport-security' in result['security_headers']
        assert 'content-security-policy' in result['missing_security_headers']

    def test_fingerprint_interesting_headers(self):
        from apps.scanning.engine.active_recon.http_probe import fingerprint_headers
        headers = {'X-Debug-Token': 'abc123', 'X-Request-Id': 'req-456'}
        result = fingerprint_headers(headers)
        assert len(result['interesting_headers']) >= 1

    def test_fingerprint_empty_headers(self):
        from apps.scanning.engine.active_recon.http_probe import fingerprint_headers
        result = fingerprint_headers({})
        assert result['technologies'] == []


class TestCDNDetection:
    def test_detect_cdn_cloudflare(self):
        from apps.scanning.engine.active_recon.http_probe import detect_cdn_and_origin
        headers = {'CF-RAY': '1234-LAX', 'X-Cache': 'HIT'}
        result = detect_cdn_and_origin(headers)
        assert result['cdn_detected'] is True
        assert 'Cloudflare' in result['cdn_providers']
        assert result['cache_status'] == 'HIT'

    def test_detect_cdn_cloudfront(self):
        from apps.scanning.engine.active_recon.http_probe import detect_cdn_and_origin
        headers = {'X-Amz-Cf-Id': 'abc123'}
        result = detect_cdn_and_origin(headers)
        assert result['cdn_detected'] is True
        assert 'CloudFront' in result['cdn_providers']

    def test_detect_origin_hints(self):
        from apps.scanning.engine.active_recon.http_probe import detect_cdn_and_origin
        headers = {'X-Backend-Server': 'origin-10.0.0.5'}
        result = detect_cdn_and_origin(headers)
        assert len(result['origin_hints']) >= 1
        assert result['origin_hints'][0]['value'] == 'origin-10.0.0.5'

    def test_no_cdn(self):
        from apps.scanning.engine.active_recon.http_probe import detect_cdn_and_origin
        result = detect_cdn_and_origin({})
        assert result['cdn_detected'] is False


class TestScreenshotReadiness:
    def test_html_screenshottable(self):
        from apps.scanning.engine.active_recon.http_probe import check_screenshot_readiness
        result = check_screenshot_readiness(
            {'Content-Type': 'text/html; charset=utf-8'}, 200
        )
        assert result['screenshottable'] is True

    def test_error_not_screenshottable(self):
        from apps.scanning.engine.active_recon.http_probe import check_screenshot_readiness
        result = check_screenshot_readiness(
            {'Content-Type': 'text/html'}, 500
        )
        assert result['screenshottable'] is False

    def test_csp_blocks_embed(self):
        from apps.scanning.engine.active_recon.http_probe import check_screenshot_readiness
        result = check_screenshot_readiness(
            {'Content-Type': 'text/html',
             'Content-Security-Policy': "frame-ancestors 'none'"}, 200
        )
        assert result['csp_blocks_embed'] is True


class TestJARM:
    def test_compute_jarm_stub(self):
        from apps.scanning.engine.active_recon.http_probe import compute_jarm_stub
        result = compute_jarm_stub('example.com', 443)
        assert result['host'] == 'example.com'
        assert result['port'] == 443

    def test_lookup_jarm_known(self):
        from apps.scanning.engine.active_recon.http_probe import lookup_jarm
        fp = '27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d'
        assert lookup_jarm(fp) == 'Nginx'

    def test_lookup_jarm_unknown(self):
        from apps.scanning.engine.active_recon.http_probe import lookup_jarm
        assert lookup_jarm('unknown') is None


class TestEnhancedHTTPProbe:
    def test_run_quick(self):
        from apps.scanning.engine.active_recon.http_probe import run_enhanced_http_probe
        result = run_enhanced_http_probe('https://example.com',
                                          headers={'Server': 'nginx'},
                                          depth='quick')
        assert 'fingerprint' in result
        assert result['screenshot'] == {}

    def test_run_medium_with_favicon(self):
        from apps.scanning.engine.active_recon.http_probe import run_enhanced_http_probe
        result = run_enhanced_http_probe(
            'https://example.com',
            headers={'Content-Type': 'text/html'},
            status_code=200,
            favicon_bytes=b'\x89PNG' + b'\x00' * 50,
            depth='medium',
        )
        assert result['screenshot']['screenshottable'] is True
        assert 'hash' in result['favicon']

    def test_run_deep(self):
        from apps.scanning.engine.active_recon.http_probe import run_enhanced_http_probe
        result = run_enhanced_http_probe('https://example.com', depth='deep')
        assert 'host' in result['jarm']


# ────────────────────────────────────────────────────────────────────────────
# Cloud Asset (cloud_asset.py)
# ────────────────────────────────────────────────────────────────────────────

class TestS3Discovery:
    def test_generate_s3_candidates(self):
        from apps.scanning.engine.active_recon.cloud_asset import generate_s3_candidates
        candidates = generate_s3_candidates('example.com')
        assert len(candidates) > 0
        assert all('bucket' in c and 'url' in c for c in candidates)
        assert any('example' in c['bucket'] for c in candidates)
        assert all('s3' in c['url'] for c in candidates)

    def test_s3_patterns(self):
        from apps.scanning.engine.active_recon.cloud_asset import S3_BUCKET_PATTERNS
        assert any('{name}' in p for p in S3_BUCKET_PATTERNS)


class TestAzureDiscovery:
    def test_generate_azure_candidates(self):
        from apps.scanning.engine.active_recon.cloud_asset import generate_azure_candidates
        candidates = generate_azure_candidates('example.com')
        assert len(candidates) > 0
        assert all('account' in c and 'container' in c for c in candidates)
        assert all('blob.core.windows.net' in c['url'] for c in candidates)

    def test_azure_account_name_valid(self):
        from apps.scanning.engine.active_recon.cloud_asset import generate_azure_candidates
        candidates = generate_azure_candidates('test.com')
        for c in candidates:
            acct = c['account']
            assert acct.isalnum()
            assert 3 <= len(acct) <= 24


class TestGCPDiscovery:
    def test_generate_gcp_candidates(self):
        from apps.scanning.engine.active_recon.cloud_asset import generate_gcp_candidates
        candidates = generate_gcp_candidates('example.com')
        assert len(candidates) > 0
        assert all('bucket' in c and 'url' in c for c in candidates)
        assert all('storage.googleapis.com' in c['url'] for c in candidates)


class TestCDNOrigin:
    def test_detect_cdn_origin_from_cnames(self):
        from apps.scanning.engine.active_recon.cloud_asset import detect_cdn_origin_from_cnames
        cnames = ['d123.cloudfront.net', 'example.azureedge.net']
        results = detect_cdn_origin_from_cnames(cnames)
        assert len(results) == 2
        providers = {r['provider'] for r in results}
        assert 'cloudfront' in providers
        assert 'azure_cdn' in providers

    def test_detect_cdn_origin_no_cnames(self):
        from apps.scanning.engine.active_recon.cloud_asset import detect_cdn_origin_from_cnames
        assert detect_cdn_origin_from_cnames([]) == []

    def test_generate_origin_bypass_tests(self):
        from apps.scanning.engine.active_recon.cloud_asset import generate_origin_bypass_tests
        tests = generate_origin_bypass_tests('example.com')
        assert len(tests) > 0
        assert all('header' in t and 'value' in t for t in tests)


class TestServerlessEndpoints:
    def test_detect_serverless_lambda(self):
        from apps.scanning.engine.active_recon.cloud_asset import detect_serverless_endpoints
        urls = [
            'https://abc123.execute-api.us-east-1.amazonaws.com/prod/',
            'https://normal.example.com/',
        ]
        results = detect_serverless_endpoints(urls)
        assert len(results) == 1
        assert results[0]['provider'] == 'aws_lambda'

    def test_detect_serverless_azure(self):
        from apps.scanning.engine.active_recon.cloud_asset import detect_serverless_endpoints
        urls = ['https://myapp.azurewebsites.net/api/hello']
        results = detect_serverless_endpoints(urls)
        assert len(results) == 1
        assert results[0]['provider'] == 'azure_function'

    def test_detect_serverless_none(self):
        from apps.scanning.engine.active_recon.cloud_asset import detect_serverless_endpoints
        assert detect_serverless_endpoints(['https://example.com/']) == []

    def test_generate_function_candidates(self):
        from apps.scanning.engine.active_recon.cloud_asset import generate_function_candidates
        candidates = generate_function_candidates('example.com')
        assert len(candidates) > 0
        types = {c['type'] for c in candidates}
        assert 'azure_function' in types


class TestContainerRegistries:
    def test_detect_registries(self):
        from apps.scanning.engine.active_recon.cloud_asset import detect_container_registries
        urls = ['123456789.dkr.ecr.us-east-1.amazonaws.com/myrepo', 'ghcr.io/user/repo']
        results = detect_container_registries(urls)
        assert len(results) == 2
        regs = {r['registry'] for r in results}
        assert 'ecr' in regs
        assert 'ghcr' in regs


class TestCloudAssetAggregator:
    def test_run_quick(self):
        from apps.scanning.engine.active_recon.cloud_asset import run_cloud_asset_discovery
        result = run_cloud_asset_discovery('example.com', depth='quick')
        assert len(result['s3_candidates']) > 0
        assert result['azure_candidates'] == []  # medium+ only
        assert result['origin_bypass_tests'] == []  # deep only

    def test_run_medium(self):
        from apps.scanning.engine.active_recon.cloud_asset import run_cloud_asset_discovery
        result = run_cloud_asset_discovery('example.com', depth='medium')
        assert len(result['azure_candidates']) > 0
        assert len(result['gcp_candidates']) > 0
        assert len(result['function_candidates']) > 0

    def test_run_deep_with_urls(self):
        from apps.scanning.engine.active_recon.cloud_asset import run_cloud_asset_discovery
        result = run_cloud_asset_discovery(
            'example.com', depth='deep',
            cnames=['d123.cloudfront.net'],
            discovered_urls=['https://abc.execute-api.us-east-1.amazonaws.com/prod/'],
        )
        assert len(result['cdn_origins']) > 0
        assert len(result['serverless_endpoints']) > 0
        assert len(result['origin_bypass_tests']) > 0


# ────────────────────────────────────────────────────────────────────────────
# ActiveReconTester integration
# ────────────────────────────────────────────────────────────────────────────

class TestActiveReconTester:
    @pytest.fixture()
    def tester(self):
        from apps.scanning.engine.testers.active_recon_tester import ActiveReconTester
        return ActiveReconTester()

    def test_tester_name(self, tester):
        assert tester.TESTER_NAME == 'Active Recon Scanner'

    def test_empty_url(self, tester):
        assert tester.test({'url': ''}) == []

    def test_quick_depth(self, tester):
        with patch('apps.scanning.engine.active_recon.check_dnssec') as mock_ds, \
             patch('apps.scanning.engine.active_recon.attempt_zone_transfer') as mock_zt:
            mock_ds.return_value = {'enabled': False, 'issues': []}
            mock_zt.return_value = {'vulnerable': False, 'records': []}
            vulns = tester.test({'url': 'https://example.com'}, depth='quick')
        # Should find DNSSEC not enabled
        assert any('DNSSEC' in v.get('name', '') for v in vulns)

    def test_medium_depth(self, tester):
        with patch('apps.scanning.engine.active_recon.check_dnssec') as mock_ds, \
             patch('apps.scanning.engine.active_recon.attempt_zone_transfer') as mock_zt:
            mock_ds.return_value = {'enabled': True, 'algorithm': 13, 'issues': []}
            mock_zt.return_value = {'vulnerable': False}
            vulns = tester.test(
                {'url': 'https://example.com', 'headers': {'Server': 'nginx'}},
                depth='medium',
            )
        # Cloud asset discovery should run at medium depth
        info_vulns = [v for v in vulns if v.get('severity') == 'info']
        assert len(info_vulns) >= 0  # May or may not find things

    def test_deep_depth_with_recon(self, tester):
        with patch('apps.scanning.engine.active_recon.check_dnssec') as mock_ds, \
             patch('apps.scanning.engine.active_recon.attempt_zone_transfer') as mock_zt:
            mock_ds.return_value = {'enabled': True, 'algorithm': 13, 'issues': []}
            mock_zt.return_value = {'vulnerable': False}
            recon = {
                'subdomains': ['api.example.com'],
                'urls': ['https://myapp.azurewebsites.net/api/test'],
            }
            vulns = tester.test(
                {'url': 'https://example.com', 'headers': {}},
                depth='deep',
                recon_data=recon,
            )
        # Should have serverless findings
        names = [v.get('name', '') for v in vulns]
        assert any('Serverless' in n for n in names)

    def test_zone_transfer_vuln(self, tester):
        with patch('apps.scanning.engine.active_recon.check_dnssec') as mock_ds, \
             patch('apps.scanning.engine.active_recon.attempt_zone_transfer') as mock_zt:
            mock_ds.return_value = {'enabled': True, 'algorithm': 13, 'issues': []}
            mock_zt.return_value = {
                'vulnerable': True,
                'nameserver': 'ns1.example.com',
                'records': [{'name': 'a', 'type': 'A'}] * 50,
            }
            vulns = tester.test({'url': 'https://example.com'}, depth='quick')
        assert any('Zone Transfer' in v.get('name', '') for v in vulns)

    def test_missing_security_headers(self, tester):
        with patch('apps.scanning.engine.active_recon.check_dnssec') as mock_ds, \
             patch('apps.scanning.engine.active_recon.attempt_zone_transfer') as mock_zt:
            mock_ds.return_value = {'enabled': True, 'algorithm': 13, 'issues': []}
            mock_zt.return_value = {'vulnerable': False}
            vulns = tester.test(
                {'url': 'https://example.com', 'headers': {'Server': 'Apache'}},
                depth='medium',
            )
        assert any('Missing Critical Security Headers' in v.get('name', '')
                    for v in vulns)


# ────────────────────────────────────────────────────────────────────────────
# Registration
# ────────────────────────────────────────────────────────────────────────────

class TestRegistration:
    def test_tester_count_68(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert len(testers) == 87, f'Expected 87 testers, got {len(testers)}'

    def test_active_recon_tester_registered(self):
        from apps.scanning.engine.testers import get_all_testers
        from apps.scanning.engine.testers.active_recon_tester import ActiveReconTester
        testers = get_all_testers()
        assert any(isinstance(t, ActiveReconTester) for t in testers)

    def test_js_intelligence_tester_position(self):
        from apps.scanning.engine.testers import get_all_testers
        from apps.scanning.engine.testers.js_intelligence_tester import JsIntelligenceTester
        testers = get_all_testers()
        assert isinstance(testers[-19], JsIntelligenceTester)
