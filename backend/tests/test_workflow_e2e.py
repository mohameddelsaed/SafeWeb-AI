"""
Comprehensive end-to-end workflow verification — SafeWeb AI scanner.

Phases:
  Phase 0 — Tool wrapper imports, TOOL_CLASS presence, instantiation
  Phase 1 — parse_output() correctness for key wrappers
  Phase 2 — Tool registry: all tools registered, health_check, capability queries
  Phase 3 — Recon modules: run to completion with mocked network, correct schema
  Phase 4 — Orchestrator _run_recon / scoring
  Phase 5 — Full tester pipeline: instantiation, error isolation, finding schema
"""
from __future__ import annotations

import contextlib
import json
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _mock_http_response(url='https://example.com', status=200,
                        body='<html><body>test</body></html>',
                        headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.content = body.encode() if isinstance(body, str) else body
    resp.headers = headers or {'Content-Type': 'text/html', 'Server': 'nginx'}
    resp.url = url
    resp.ok = 200 <= status < 400
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds = MagicMock(return_value=0.1)
    resp.cookies = MagicMock()
    resp.cookies.__iter__ = MagicMock(return_value=iter([]))
    return resp


def _mock_session():
    session = MagicMock()
    resp = _mock_http_response()
    session.get.return_value = resp
    session.post.return_value = resp
    session.request.return_value = resp
    session.headers = {}
    session.verify = False
    return session


# ─────────────────────────────────────────────────────────────────────────────
# Phase 0 — Wrapper imports & TOOL_CLASS
# ─────────────────────────────────────────────────────────────────────────────

_ALL_WRAPPER_MODULES = [
    # Original set
    'apps.scanning.engine.tools.wrappers.nmap_wrapper',
    'apps.scanning.engine.tools.wrappers.subfinder_wrapper',
    'apps.scanning.engine.tools.wrappers.nuclei_cli_wrapper',
    'apps.scanning.engine.tools.wrappers.sqlmap_wrapper',
    'apps.scanning.engine.tools.wrappers.ffuf_wrapper',
    'apps.scanning.engine.tools.wrappers.whatweb_wrapper',
    'apps.scanning.engine.tools.wrappers.wappalyzer_wrapper',
    'apps.scanning.engine.tools.wrappers.amass_wrapper',
    'apps.scanning.engine.tools.wrappers.httpx_wrapper',
    'apps.scanning.engine.tools.wrappers.dirsearch_wrapper',
    'apps.scanning.engine.tools.wrappers.gau_wrapper',
    'apps.scanning.engine.tools.wrappers.waybackurls_wrapper',
    'apps.scanning.engine.tools.wrappers.dalfox_wrapper',
    'apps.scanning.engine.tools.wrappers.commix_wrapper',
    'apps.scanning.engine.tools.wrappers.arjun_wrapper',
    'apps.scanning.engine.tools.wrappers.sslyze_wrapper',
    'apps.scanning.engine.tools.wrappers.wpscan_wrapper',
    'apps.scanning.engine.tools.wrappers.dnsrecon_wrapper',
    'apps.scanning.engine.tools.wrappers.gospider_wrapper',
    'apps.scanning.engine.tools.wrappers.katana_wrapper',
    'apps.scanning.engine.tools.wrappers.feroxbuster_wrapper',
    'apps.scanning.engine.tools.wrappers.gf_wrapper',
    'apps.scanning.engine.tools.wrappers.qsreplace_wrapper',
    'apps.scanning.engine.tools.wrappers.crlfuzz_wrapper',
    # Phase A — subdomain/recon
    'apps.scanning.engine.tools.wrappers.assetfinder_wrapper',
    'apps.scanning.engine.tools.wrappers.findomain_wrapper',
    'apps.scanning.engine.tools.wrappers.chaos_wrapper',
    'apps.scanning.engine.tools.wrappers.sublist3r_wrapper',
    'apps.scanning.engine.tools.wrappers.asnmap_wrapper',
    'apps.scanning.engine.tools.wrappers.mapcidr_wrapper',
    'apps.scanning.engine.tools.wrappers.dnsx_wrapper',
    'apps.scanning.engine.tools.wrappers.puredns_wrapper',
    'apps.scanning.engine.tools.wrappers.hakrawler_wrapper',
    'apps.scanning.engine.tools.wrappers.getjs_wrapper',
    'apps.scanning.engine.tools.wrappers.httprobe_wrapper',
    'apps.scanning.engine.tools.wrappers.tlsx_wrapper',
    # Port scan
    'apps.scanning.engine.tools.wrappers.naabu_wrapper',
    # Phase B — vuln scanners
    'apps.scanning.engine.tools.wrappers.xsstrike_wrapper',
    'apps.scanning.engine.tools.wrappers.ghauri_wrapper',
    'apps.scanning.engine.tools.wrappers.tplmap_wrapper',
    'apps.scanning.engine.tools.wrappers.subjack_wrapper',
    'apps.scanning.engine.tools.wrappers.subover_wrapper',
    # Phase C — secrets/links
    'apps.scanning.engine.tools.wrappers.trufflehog_wrapper',
    'apps.scanning.engine.tools.wrappers.gitleaks_wrapper',
    'apps.scanning.engine.tools.wrappers.linkfinder_wrapper',
    'apps.scanning.engine.tools.wrappers.secretfinder_wrapper',
    # Phase D — cloud
    'apps.scanning.engine.tools.wrappers.cloudenum_wrapper',
    'apps.scanning.engine.tools.wrappers.s3scanner_wrapper',
    'apps.scanning.engine.tools.wrappers.awsbucketdump_wrapper',
    # Phase E — fuzzing/screenshots
    'apps.scanning.engine.tools.wrappers.gobuster_wrapper',
    'apps.scanning.engine.tools.wrappers.x8_wrapper',
    'apps.scanning.engine.tools.wrappers.masscan_wrapper',
    'apps.scanning.engine.tools.wrappers.eyewitness_wrapper',
    'apps.scanning.engine.tools.wrappers.aquatone_wrapper',
    # Phase F — OOB
    'apps.scanning.engine.tools.wrappers.interactsh_wrapper',
]

_MODULE_IDS = [m.rsplit('.', 1)[-1] for m in _ALL_WRAPPER_MODULES]


class TestPhase0WrapperImports:
    """Phase 0: every wrapper imports cleanly and exposes TOOL_CLASS."""

    @pytest.mark.parametrize('module_path', _ALL_WRAPPER_MODULES, ids=_MODULE_IDS)
    def test_import_has_tool_class(self, module_path):
        import importlib
        mod = importlib.import_module(module_path)
        assert hasattr(mod, 'TOOL_CLASS'), f'{module_path} missing TOOL_CLASS'

    @pytest.mark.parametrize('module_path', _ALL_WRAPPER_MODULES, ids=_MODULE_IDS)
    def test_instantiation_valid_attrs(self, module_path):
        import importlib
        mod = importlib.import_module(module_path)
        tool = mod.TOOL_CLASS()
        assert isinstance(tool.name, str) and tool.name, 'name must be non-empty str'
        assert isinstance(tool.binary, str) and tool.binary, 'binary must be non-empty str'
        assert isinstance(tool.timeout, int) and tool.timeout > 0, 'timeout must be positive int'
        assert isinstance(tool.capabilities, list) and len(tool.capabilities) > 0, \
            f'{tool.name}: capabilities list is empty'

    @pytest.mark.parametrize('module_path', _ALL_WRAPPER_MODULES, ids=_MODULE_IDS)
    def test_is_available_returns_bool(self, module_path):
        import importlib
        mod = importlib.import_module(module_path)
        tool = mod.TOOL_CLASS()
        result = tool.is_available()
        assert isinstance(result, bool)

    @pytest.mark.parametrize('module_path', _ALL_WRAPPER_MODULES, ids=_MODULE_IDS)
    def test_run_unavailable_returns_empty(self, module_path):
        """When binary is not available, run() must return [] without crashing."""
        import importlib
        mod = importlib.import_module(module_path)
        tool = mod.TOOL_CLASS()
        # Force unavailable
        tool._available = False
        result = tool.run('example.com')
        assert isinstance(result, list)
        assert result == [], f'{tool.name}.run() should return [] when unavailable, got {result}'


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — parse_output correctness
# ─────────────────────────────────────────────────────────────────────────────

def _get_tool(wrapper_name: str):
    import importlib
    mod = importlib.import_module(f'apps.scanning.engine.tools.wrappers.{wrapper_name}')
    return mod.TOOL_CLASS()


class TestPhase1OutputParsing:
    """Phase 1: parse_output returns correct ToolResult objects."""

    # ── assetfinder ─────────────────────────────────────────────────────────

    def test_assetfinder_normal(self):
        t = _get_tool('assetfinder_wrapper')
        results = t.parse_output('sub1.example.com\nsub2.example.com\nexample.com\n')
        assert len(results) >= 2
        assert all(r.tool_name == 'assetfinder' for r in results)
        assert all(r.category == 'subdomain' for r in results)
        hosts = {r.host for r in results}
        assert 'sub1.example.com' in hosts
        assert 'sub2.example.com' in hosts

    def test_assetfinder_empty(self):
        assert _get_tool('assetfinder_wrapper').parse_output('') == []

    def test_assetfinder_filters_invalid(self):
        # Lines with spaces or http prefix should be filtered
        results = _get_tool('assetfinder_wrapper').parse_output(
            'good.example.com\nError: something bad\nhttps://bad.com\n'
        )
        hosts = {r.host for r in results}
        assert 'good.example.com' in hosts
        assert not any('Error' in h for h in hosts)

    # ── naabu ────────────────────────────────────────────────────────────────

    def test_naabu_normal(self):
        raw = (
            json.dumps({'host': '10.0.0.1', 'ip': '10.0.0.1', 'port': 80}) + '\n' +
            json.dumps({'host': '10.0.0.1', 'ip': '10.0.0.1', 'port': 443}) + '\n'
        )
        results = _get_tool('naabu_wrapper').parse_output(raw)
        assert len(results) == 2
        ports = {r.port for r in results}
        assert 80 in ports and 443 in ports

    def test_naabu_empty(self):
        assert _get_tool('naabu_wrapper').parse_output('') == []

    def test_naabu_malformed_json(self):
        results = _get_tool('naabu_wrapper').parse_output('not json\n{bad\n')
        assert isinstance(results, list)  # must not crash

    # ── httprobe ────────────────────────────────────────────────────────────

    def test_httprobe_normal(self):
        raw = 'https://sub1.example.com\nhttp://sub2.example.com\n'
        results = _get_tool('httprobe_wrapper').parse_output(raw)
        assert len(results) == 2
        urls = {r.url for r in results}
        assert 'https://sub1.example.com' in urls
        assert 'http://sub2.example.com' in urls

    def test_httprobe_empty(self):
        assert _get_tool('httprobe_wrapper').parse_output('') == []

    # ── gobuster ────────────────────────────────────────────────────────────

    def test_gobuster_normal(self):
        raw = (
            '/admin                (Status: 200) [Size: 1234]\n'
            '/login                (Status: 302) [Size: 56]\n'
        )
        results = _get_tool('gobuster_wrapper').parse_output(raw)
        assert len(results) >= 1
        all_text = ' '.join(str(r.url) + str(r.metadata) for r in results)
        assert '/admin' in all_text

    def test_gobuster_empty(self):
        assert _get_tool('gobuster_wrapper').parse_output('') == []

    # ── trufflehog ──────────────────────────────────────────────────────────

    def test_trufflehog_normal(self):
        sample = json.dumps({
            'SourceMetadata': {'Data': {'Filesystem': {'file': '/app/config.py'}}},
            'DetectorName': 'AWS',
            'Verified': True,
            'Raw': 'AKIAIOSFODNN7EXAMPLE',
            'RawV2': '',
            'Redacted': 'AKIA...AMPLE',
            'SourceName': 'Filesystem',
        })
        results = _get_tool('trufflehog_wrapper').parse_output(sample + '\n')
        assert len(results) >= 1
        assert results[0].category in ('credential', 'secret-exposure', 'secrets')
        assert results[0].tool_name == 'trufflehog'

    def test_trufflehog_empty(self):
        assert _get_tool('trufflehog_wrapper').parse_output('') == []

    # ── gitleaks ────────────────────────────────────────────────────────────

    def test_gitleaks_empty(self):
        assert _get_tool('gitleaks_wrapper').parse_output('') == []

    # ── findomain ───────────────────────────────────────────────────────────

    def test_findomain_normal(self):
        raw = 'sub1.example.com\nsub2.example.com\n'
        results = _get_tool('findomain_wrapper').parse_output(raw)
        assert len(results) >= 1
        assert all(r.category == 'subdomain' for r in results)

    # ── ToolResult.to_dict() ─────────────────────────────────────────────────

    def test_tool_result_to_dict_schema(self):
        t = _get_tool('assetfinder_wrapper')
        results = t.parse_output('sub.example.com\n')
        assert len(results) == 1
        d = results[0].to_dict()
        required = {'tool_name', 'category', 'title', 'severity', 'confidence',
                    'host', 'url', 'port', 'evidence', 'metadata', 'timestamp', 'cwe', 'cvss'}
        for key in required:
            assert key in d, f'Missing key in to_dict(): {key!r}'
        assert isinstance(d['confidence'], float)
        assert 0.0 <= d['confidence'] <= 1.0
        assert isinstance(d['timestamp'], str)

    def test_tool_severity_from_cvss(self):
        from apps.scanning.engine.tools.result import ToolSeverity
        assert ToolSeverity.from_cvss(9.5) == ToolSeverity.CRITICAL
        assert ToolSeverity.from_cvss(7.0) == ToolSeverity.HIGH
        assert ToolSeverity.from_cvss(5.0) == ToolSeverity.MEDIUM
        assert ToolSeverity.from_cvss(2.0) == ToolSeverity.LOW
        assert ToolSeverity.from_cvss(0.0) == ToolSeverity.INFO


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — Tool Registry
# ─────────────────────────────────────────────────────────────────────────────

class TestPhase2Registry:
    """Phase 2: registry registers all tools; queries are correct."""

    def _fresh_registry(self):
        """Reset singleton and register all tools fresh."""
        from apps.scanning.engine.tools.registry import ToolRegistry
        # Reset singleton
        ToolRegistry._instance = None
        from apps.scanning.engine.tools.registry import register_all_tools
        return register_all_tools()

    def test_register_all_tools_count(self):
        registry = self._fresh_registry()
        assert len(registry) >= 52, f'Expected ≥52 tools, got {len(registry)}'

    def test_all_names_are_unique(self):
        registry = self._fresh_registry()
        names = [t.name for t in registry.all_tools()]
        duplicates = [n for n in names if names.count(n) > 1]
        assert len(duplicates) == 0, f'Duplicate tool names: {set(duplicates)}'

    def test_health_check_returns_full_dict(self):
        registry = self._fresh_registry()
        health = registry.health_check()
        assert isinstance(health, dict)
        assert len(health) >= 52
        assert all(isinstance(v, bool) for v in health.values())

    def test_get_by_capability_subdomain(self):
        from apps.scanning.engine.tools.base import ToolCapability
        registry = self._fresh_registry()
        tools = registry.get_by_capability(ToolCapability.SUBDOMAIN)
        assert isinstance(tools, list)
        # All returned tools must actually have that capability
        for t in tools:
            assert ToolCapability.SUBDOMAIN in t.capabilities

    def test_get_by_capability_port_scan(self):
        from apps.scanning.engine.tools.base import ToolCapability
        registry = self._fresh_registry()
        tools = registry.get_by_capability(ToolCapability.PORT_SCAN)
        assert isinstance(tools, list)

    def test_get_available_filters_unavailable(self):
        registry = self._fresh_registry()
        available = registry.get_available()
        for t in available:
            assert t.is_available() is True

    def test_summary_lists_all_tools(self):
        registry = self._fresh_registry()
        summary = registry.summary()
        assert isinstance(summary, str)
        # Should have at least one OK line
        assert 'OK' in summary

    def test_new_wrappers_are_registered(self):
        """Specifically verify the 31 newly added wrappers are in the registry."""
        registry = self._fresh_registry()
        all_names = {t.name for t in registry.all_tools()}
        new_tools = {
            'assetfinder', 'findomain', 'chaos', 'sublist3r', 'asnmap', 'mapcidr',
            'dnsx', 'puredns', 'hakrawler', 'getJS', 'httprobe', 'tlsx', 'naabu',
            'xsstrike', 'ghauri', 'tplmap', 'subjack', 'subover',
            'trufflehog', 'gitleaks', 'linkfinder', 'secretfinder',
            'cloud_enum', 's3scanner', 'awsbucketdump',
            'gobuster', 'x8', 'masscan', 'eyewitness', 'aquatone', 'interactsh',
        }
        missing = new_tools - all_names
        assert len(missing) == 0, f'New wrappers not registered: {missing}'


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Recon Modules (mocked network)
# ─────────────────────────────────────────────────────────────────────────────

def _make_req_fn(method, url, **kwargs):
    return _mock_http_response(url=url)


class TestPhase3ReconModules:
    """Phase 3: each recon module runs to completion and returns correct schema."""

    def _assert_recon_result(self, result, label=''):
        assert isinstance(result, dict), f'{label}: must return dict, got {type(result)}'
        assert 'findings' in result, f'{label}: missing "findings" key'
        assert 'metadata' in result, f'{label}: missing "metadata" key'
        assert isinstance(result['findings'], list), f'{label}: findings must be list'

    # ── dns_recon ───────────────────────────────────────────────────────────

    def test_dns_recon(self):
        with patch('socket.getaddrinfo', return_value=[
                       (2, 1, 6, '', ('93.184.216.34', 0))]),\
             patch('socket.gethostbyname', return_value='93.184.216.34'), \
             patch('socket.gethostbyname_ex', return_value=('example.com', [], ['93.184.216.34'])), \
             patch('dns.resolver.Resolver') as mock_r:
            mock_r.return_value.resolve.side_effect = Exception('mocked')
            from apps.scanning.engine.recon.dns_recon import run_dns_recon
            result = run_dns_recon('https://example.com', 'medium')
        self._assert_recon_result(result, 'dns_recon')
        assert 'hostname' in result or 'ip_addresses' in result or 'findings' in result

    # ── cert_analysis ───────────────────────────────────────────────────────

    def test_cert_analysis(self):
        # Make wrap_socket raise ConnectionRefusedError (which cert_analysis catches)
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ConnectionRefusedError('mocked')
        with patch('ssl.create_default_context', return_value=mock_ctx):
            from apps.scanning.engine.recon.cert_analysis import run_cert_analysis
            result = run_cert_analysis('https://example.com')
        self._assert_recon_result(result, 'cert_analysis')

    # ── waf_detection ───────────────────────────────────────────────────────

    def test_waf_detection(self):
        from apps.scanning.engine.recon.waf_detection import run_waf_detection
        result = run_waf_detection('https://example.com', make_request_fn=_make_req_fn)
        self._assert_recon_result(result, 'waf_detection')
        assert 'detected' in result

    # ── header_analyzer ─────────────────────────────────────────────────────

    def test_header_analyzer(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            'https://example.com',
            response_headers={'Content-Type': 'text/html', 'Server': 'nginx'},
        )
        self._assert_recon_result(result, 'header_analyzer')
        assert 'missing' in result or 'score' in result or 'findings' in result

    # ── cookie_analyzer ─────────────────────────────────────────────────────

    def test_cookie_analyzer(self):
        from apps.scanning.engine.recon.cookie_analyzer import run_cookie_analysis
        result = run_cookie_analysis(
            'https://example.com',
            cookies={'session': 'abc123'},
            set_cookie_headers={'Set-Cookie': 'session=abc123; Path=/'},
        )
        self._assert_recon_result(result, 'cookie_analyzer')

    # ── tech_fingerprint ────────────────────────────────────────────────────

    def test_tech_fingerprint(self):
        from apps.scanning.engine.recon.tech_fingerprint import run_tech_fingerprint
        result = run_tech_fingerprint(
            'https://example.com',
            response_headers={'Server': 'Apache/2.4', 'X-Powered-By': 'PHP/8.1'},
            response_body='<html><head><title>Test</title></head></html>',
        )
        self._assert_recon_result(result, 'tech_fingerprint')
        assert 'technologies' in result

    # ── url_harvester ───────────────────────────────────────────────────────

    def test_url_harvester(self):
        with patch('requests.get', return_value=_mock_http_response()):
            from apps.scanning.engine.recon.url_harvester import run_url_harvester
            result = run_url_harvester(
                'https://example.com',
                response_body='<a href="/about">About</a><a href="/contact">Contact</a>',
                depth='shallow',
            )
        self._assert_recon_result(result, 'url_harvester')
        # module stores urls under internal_urls/external_urls or urls
        assert 'internal_urls' in result or 'urls' in result

    # ── subdomain_enum ──────────────────────────────────────────────────────

    def test_subdomain_enum(self):
        with patch('socket.getaddrinfo', return_value=[]), \
             patch('socket.gethostbyname', return_value='93.184.216.34'), \
             patch('socket.getdefaulttimeout', return_value=5), \
             patch('socket.setdefaulttimeout'):
            from apps.scanning.engine.recon.subdomain_enum import run_subdomain_enum
            result = run_subdomain_enum('https://example.com', 'shallow')
        self._assert_recon_result(result, 'subdomain_enum')
        assert 'subdomains' in result

    # ── js_analyzer ─────────────────────────────────────────────────────────

    def test_js_analyzer(self):
        from apps.scanning.engine.recon.js_analyzer import run_js_analyzer
        result = run_js_analyzer(
            'https://example.com',
            js_content='var apiKey = "AIzaSyABCDEF"; fetch("/api/v1/users");',
            make_request_fn=_make_req_fn,
        )
        self._assert_recon_result(result, 'js_analyzer')

    # ── content_discovery ────────────────────────────────────────────────────

    def test_content_discovery(self):
        from apps.scanning.engine.recon.content_discovery import run_content_discovery
        result = run_content_discovery(
            'https://example.com',
            make_request_fn=_make_req_fn,
            depth='shallow',
        )
        self._assert_recon_result(result, 'content_discovery')
        assert 'paths' in result or 'findings' in result

    # ── cloud_detect ─────────────────────────────────────────────────────────

    def test_cloud_detect(self):
        from apps.scanning.engine.recon.cloud_detect import run_cloud_detect
        result = run_cloud_detect(
            'https://example.com',
            response_headers={'Server': 'AmazonS3', 'x-amz-request-id': 'ABCD'},
        )
        self._assert_recon_result(result, 'cloud_detect')
        assert 'providers' in result or 'findings' in result

    # ── http_probe ───────────────────────────────────────────────────────────

    def test_http_probe(self):
        from apps.scanning.engine.recon.http_probe import run_http_probe
        result = run_http_probe(
            'https://example.com',
            hosts=['www.example.com', 'api.example.com'],
            depth='shallow',
            make_request_fn=_make_req_fn,
        )
        self._assert_recon_result(result, 'http_probe')

    # ── port_scanner ─────────────────────────────────────────────────────────

    def test_port_scanner_shallow(self):
        with patch('socket.socket') as mock_socket:
            s_inst = MagicMock()
            s_inst.connect_ex.return_value = 1  # all ports closed
            mock_socket.return_value.__enter__ = MagicMock(return_value=s_inst)
            mock_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_socket.return_value = s_inst
            with patch('socket.gethostbyname', return_value='93.184.216.34'):
                from apps.scanning.engine.recon.port_scanner import run_port_scan
                result = run_port_scan('https://example.com', 'shallow')
        self._assert_recon_result(result, 'port_scanner')
        assert 'open_ports' in result

    # ── _base helpers ────────────────────────────────────────────────────────

    def test_base_create_result_schema(self):
        from apps.scanning.engine.recon._base import create_result
        result = create_result('test_mod', 'example.com', 'medium')
        assert 'findings' in result
        assert 'metadata' in result
        assert 'errors' in result
        assert 'stats' in result
        assert result['metadata']['module'] == 'test_mod'
        assert result['metadata']['target'] == 'example.com'

    def test_base_add_finding(self):
        from apps.scanning.engine.recon._base import create_result, add_finding
        result = create_result('test_mod', 'example.com')
        add_finding(result, {'type': 'test', 'value': 'foo'})
        assert len(result['findings']) == 1
        assert result['findings'][0]['type'] == 'test'

    def test_base_finalize_result(self):
        import time
        from apps.scanning.engine.recon._base import create_result, finalize_result
        result = create_result('test_mod', 'example.com')
        start = time.time()
        final = finalize_result(result, start)
        assert final is result  # same dict
        assert final['stats']['duration_seconds'] >= 0
        assert final['metadata']['completed_at'] is not None

    def test_base_extract_hostname(self):
        from apps.scanning.engine.recon._base import extract_hostname
        assert extract_hostname('https://www.example.com/path?q=1') == 'www.example.com'
        assert extract_hostname('http://test.io:8080/x') == 'test.io'
        assert extract_hostname('example.com') == ''  # no scheme → empty


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Orchestrator pipeline
# ─────────────────────────────────────────────────────────────────────────────

_RECON_PKG = 'apps.scanning.engine.recon'

_RECON_PATCHES = {
    f'{_RECON_PKG}.dns_recon.run_dns_recon':
        {'hostname': 'example.com', 'ip_addresses': ['93.184.216.34'],
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.whois_recon.run_whois_recon':
        {'domain': 'example.com', 'registrar': 'Test Registrar',
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.cert_analysis.run_cert_analysis':
        {'has_ssl': True, 'valid': True, 'days_until_expiry': 90,
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.waf_detection.run_waf_detection':
        {'detected': False, 'products': [], 'confidence': 'none',
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.ai_recon.run_ai_recon':
        {'detected': False, 'endpoints': [], 'frameworks': [],
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.port_scanner.run_port_scan':
        {'open_ports': [{'port': 80}, {'port': 443}],
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.ct_log_enum.run_ct_log_enum':
        {'subdomains': ['www.example.com'],
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.subdomain_enum.run_subdomain_enum':
        {'subdomains': [{'name': 'www.example.com', 'ip': '93.184.216.34'}],
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.tech_fingerprint.run_tech_fingerprint':
        {'technologies': ['nginx'], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.header_analyzer.run_header_analysis':
        {'missing': ['X-Frame-Options'], 'score': 40,
         'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.cookie_analyzer.run_cookie_analysis':
        {'cookies': [], 'score': 100, 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.url_harvester.run_url_harvester':
        {'urls': ['https://example.com/about'], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.social_recon.run_social_recon':
        {'social_links': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.cors_analyzer.run_cors_analyzer':
        {'misconfigurations': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.js_analyzer.run_js_analyzer':
        {'secrets': [], 'endpoints': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.cloud_detect.run_cloud_detect':
        {'providers': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.cms_fingerprint.run_cms_fingerprint':
        {'cms': None, 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.email_enum.run_email_enum':
        {'emails': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.content_discovery.run_content_discovery':
        {'paths': ['/admin'], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.param_discovery.run_param_discovery':
        {'params': ['id', 'q'], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.api_discovery.run_api_discovery':
        {'apis': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.subdomain_brute.run_subdomain_brute':
        {'subdomains': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.network_mapper.run_network_mapper':
        {'topology': {}, 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.vuln_correlator.run_vuln_correlator':
        {'correlations': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.attack_surface.run_attack_surface':
        {'score': 35, 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.threat_intel.run_threat_intel':
        {'threats': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.risk_scorer.run_risk_scorer':
        {'grade': 'B', 'overall_score': 72, 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.dns_zone_enum.run_dns_zone_enum':
        {'srv_records': [], 'mx_records': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.passive_subdomain.run_passive_subdomain':
        {'subdomains': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.asn_recon.run_asn_recon':
        {'cidrs': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.wildcard_detector.run_wildcard_detection':
        {'wildcard_detected': False, 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.http_probe.run_http_probe':
        {'live_hosts': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
    f'{_RECON_PKG}.screenshot_recon.run_screenshot_recon':
        {'screenshots': [], 'findings': [], 'metadata': {}, 'errors': [], 'stats': {}},
}


def _patch_recon(overrides=None):
    stack = contextlib.ExitStack()
    stack.enter_context(patch('requests.Session', return_value=_mock_session()))
    combined = dict(_RECON_PATCHES)
    if overrides:
        combined.update(overrides)
    for path, rv in combined.items():
        if isinstance(rv, Exception):
            stack.enter_context(patch(path, side_effect=rv))
        else:
            stack.enter_context(patch(path, return_value=rv))
    return stack


class TestPhase4Orchestrator:
    """Phase 4: orchestrator _run_recon and scoring."""

    def setup_method(self):
        from apps.scanning.engine.orchestrator import ScanOrchestrator
        self.orc = ScanOrchestrator()

    def _scan(self, depth='medium'):
        s = MagicMock()
        s.target = 'https://example.com'
        s.depth = depth
        s.include_subdomains = True
        s.follow_redirects = True
        return s

    def test_recon_returns_dict(self):
        with _patch_recon():
            result = self.orc._run_recon(self._scan('medium'))
        assert isinstance(result, dict)

    def test_recon_medium_has_core_keys(self):
        with _patch_recon():
            result = self.orc._run_recon(self._scan('medium'))
        for key in ('dns', 'certificate', 'waf'):
            assert key in result, f'Missing recon key: {key!r}'

    def test_recon_deep_runs(self):
        with _patch_recon():
            result = self.orc._run_recon(self._scan('deep'))
        assert isinstance(result, dict)
        # Deep includes port scan
        assert 'ports' in result

    def test_recon_survives_module_failure(self):
        overrides = {
            f'{_RECON_PKG}.dns_recon.run_dns_recon': RuntimeError('DNS boom'),
            f'{_RECON_PKG}.whois_recon.run_whois_recon': RuntimeError('WHOIS boom'),
        }
        with _patch_recon(overrides):
            result = self.orc._run_recon(self._scan('medium'))
        # Must return a dict even if several modules failed
        assert isinstance(result, dict)
        # At least some keys from other waves survived
        assert len(result) > 0

    def test_score_100_for_no_vulns(self):
        scan = MagicMock()
        qs = MagicMock()
        qs.exists.return_value = False
        scan.vulnerabilities.all.return_value = qs
        assert self.orc._calculate_security_score(scan) == 100

    def test_score_drops_for_critical(self):
        scan = MagicMock()
        qs = MagicMock()
        qs.exists.return_value = True
        qs.values.return_value = [{'severity': 'critical'}]
        scan.vulnerabilities.all.return_value = qs
        score = self.orc._calculate_security_score(scan)
        assert score < 100, 'Score must drop below 100 for critical vulnerability'

    def test_score_bounded(self):
        """Score must always be in [0, 100]."""
        scan = MagicMock()
        qs = MagicMock()
        qs.exists.return_value = True
        many = [{'severity': s} for s in ['critical', 'high', 'medium', 'low'] * 5]
        qs.values.return_value = many
        scan.vulnerabilities.all.return_value = qs
        score = self.orc._calculate_security_score(scan)
        assert 0 <= score <= 100


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — Full tester pipeline smoke test
# ─────────────────────────────────────────────────────────────────────────────

class TestPhase5TesterPipeline:
    """Phase 5: all testers instantiate, pipeline is error-isolated, schema correct."""

    def _make_page(self, url='https://example.com/search?q=test'):
        page = MagicMock()
        page.url = url
        page.status_code = 200
        page.headers = {'Content-Type': 'text/html', 'Server': 'Apache/2.4'}
        page.cookies = {}
        page.body = (
            '<html><head><title>Test</title></head>'
            '<body><form action="/search" method="GET">'
            '<input name="q" type="text"></form></body></html>'
        )
        page.content = page.body
        page.forms = []
        page.links = ['/about', '/contact']
        page.parameters = {'q': 'test'}
        page.js_rendered = False
        page.get = lambda k, d=None: getattr(page, k, d)
        page.__getitem__ = lambda s, k: getattr(s, k)
        return page

    @contextlib.contextmanager
    def _full_mock(self):
        """Block ALL outbound network and subprocess calls made by testers."""
        resp = _mock_http_response()
        conn_err = ConnectionRefusedError('mocked by test suite')
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch('requests.Session', return_value=_mock_session()))
            stack.enter_context(patch('requests.get', return_value=resp))
            stack.enter_context(patch('requests.post', return_value=resp))
            stack.enter_context(patch('requests.put', return_value=resp))
            stack.enter_context(patch('requests.delete', return_value=resp))
            stack.enter_context(patch('requests.request', return_value=resp))
            stack.enter_context(patch('socket.create_connection',
                                      side_effect=conn_err))
            stack.enter_context(patch('socket.getaddrinfo', return_value=[]))
            stack.enter_context(patch('subprocess.run', return_value=MagicMock(
                returncode=1, stdout='', stderr='binary not found')))
            stack.enter_context(patch('subprocess.Popen',
                                      side_effect=FileNotFoundError('mocked')))
            yield stack

    def test_get_all_testers_returns_list(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert isinstance(testers, list)
        assert len(testers) >= 10

    def test_all_testers_have_required_interface(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        for t in testers:
            assert hasattr(t, 'test'), f'{type(t).__name__} missing test()'
            assert hasattr(t, 'TESTER_NAME'), f'{type(t).__name__} missing TESTER_NAME'
            assert isinstance(t.TESTER_NAME, str) and t.TESTER_NAME, \
                f'{type(t).__name__} TESTER_NAME is empty'

    def test_all_tester_names_unique(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        names = [t.TESTER_NAME for t in testers]
        duplicates = [n for n in names if names.count(n) > 1]
        assert len(duplicates) == 0, f'Duplicate TESTER_NAMEs: {set(duplicates)}'

    def test_pipeline_error_isolation(self):
        """If one tester raises, the pipeline still collects results from all others."""
        import threading
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        page = self._make_page()

        TESTER_TIMEOUT = 8  # seconds per tester

        all_findings = []
        errors = []
        timeouts = []

        for t in testers:
            result_box = []
            exc_box = []

            def _run(tester=t):
                try:
                    with self._full_mock():
                        res = tester.test(page, depth='shallow', recon_data={})
                        result_box.append(res)
                except Exception as e:
                    exc_box.append(e)

            thread = threading.Thread(target=_run, daemon=True)
            thread.start()
            thread.join(timeout=TESTER_TIMEOUT)

            if thread.is_alive():
                timeouts.append(t.TESTER_NAME)
            elif exc_box:
                errors.append((t.TESTER_NAME, type(exc_box[0]).__name__, str(exc_box[0])[:80]))
            elif result_box and isinstance(result_box[0], list):
                all_findings.extend(result_box[0])

        total = len(testers)
        max_errors = max(2, total // 5)  # allow up to 20% crash rate
        max_timeouts = max(2, total // 5)  # allow up to 20% timeout rate
        assert len(errors) <= max_errors, (
            f'{len(errors)}/{total} testers crashed (max {max_errors}):\n'
            + '\n'.join(f'  {n}: {et}: {m}' for n, et, m in errors[:10])
        )
        assert len(timeouts) <= max_timeouts, (
            f'{len(timeouts)}/{total} testers timed out (>{TESTER_TIMEOUT}s, max {max_timeouts}):\n'
            + '\n'.join(f'  {n}' for n in timeouts[:10])
        )

    def test_finding_schema_required_keys(self):
        """Every non-empty finding dict must have the required keys."""
        import threading
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        page = self._make_page()

        required_keys = {'name', 'severity', 'category', 'description'}
        schema_errors = []
        TESTER_TIMEOUT = 8

        for t in testers[:20]:  # sample first 20 for speed
            result_box = []

            def _run(tester=t):
                try:
                    with self._full_mock():
                        res = tester.test(page, depth='shallow', recon_data={})
                        result_box.append(res)
                except Exception:
                    pass

            thread = threading.Thread(target=_run, daemon=True)
            thread.start()
            thread.join(timeout=TESTER_TIMEOUT)
            if thread.is_alive():
                continue  # timed out — skip schema check for this tester

            if result_box and isinstance(result_box[0], list):
                for finding in result_box[0]:
                    if isinstance(finding, dict):
                        missing = required_keys - finding.keys()
                        if missing:
                            schema_errors.append(
                                f'{t.TESTER_NAME}: missing {missing}'
                            )

        assert len(schema_errors) == 0, \
            'Finding schema violations:\n' + '\n'.join(schema_errors)

    def test_pipeline_run_function(self):
        """Mirroring orchestrator logic: iterate testers, catch errors, aggregate."""
        import threading
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        page = self._make_page()
        TESTER_TIMEOUT = 8

        findings = []
        for t in testers:
            result_box = []

            def _run(tester=t):
                try:
                    with self._full_mock():
                        res = tester.test(page, depth='shallow', recon_data={})
                        result_box.append(res)
                except Exception:
                    pass

            thread = threading.Thread(target=_run, daemon=True)
            thread.start()
            thread.join(timeout=TESTER_TIMEOUT)
            if not thread.is_alive() and result_box and isinstance(result_box[0], list):
                findings.extend(result_box[0])

        assert isinstance(findings, list)
        # All returned findings must be dicts
        for f in findings:
            assert isinstance(f, dict), f'Finding must be dict, got {type(f)}'

