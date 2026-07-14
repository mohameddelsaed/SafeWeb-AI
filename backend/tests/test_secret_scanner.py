"""
Tests for Phase 25 — Secret Scanner & Data Leak Detection.

Covers:
  - Pattern library (patterns.py): Pattern count, severity distribution, regex validity
  - SecretScanner: Pattern / entropy / base64 detection, dedup, redaction
  - GitDumper: .git exposure probe, metadata extraction, secret extraction
  - Integration: Import checks, vuln dict format, orchestrator wiring
"""

import re
from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch, PropertyMock



# ---------------------------------------------------------------------------
# Lightweight page stub (same pattern as conftest.MockPage)
# ---------------------------------------------------------------------------
@dataclass
class _Page:
    url: str = 'https://example.com/'
    body: str = ''
    status_code: int = 200
    headers: dict = field(default_factory=dict)


# ===========================================================================
# 1. Pattern Library Tests
# ===========================================================================
class TestPatternLibrary:
    """Tests for secrets.patterns module."""

    def test_pattern_count_over_150(self):
        from apps.scanning.engine.secrets.patterns import PATTERN_COUNT
        assert PATTERN_COUNT >= 150, f'Expected 150+ patterns, got {PATTERN_COUNT}'

    def test_all_patterns_have_required_keys(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        required = {'name', 'regex', 'severity', 'cwe', 'description'}
        for pat in SECRET_PATTERNS:
            assert required.issubset(pat.keys()), f'Pattern {pat.get("name", "?")} missing keys'

    def test_all_patterns_compile(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        for pat in SECRET_PATTERNS:
            assert isinstance(pat['regex'], re.Pattern), (
                f'Pattern {pat["name"]} is not compiled'
            )

    def test_valid_severities(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        valid = {'critical', 'high', 'medium', 'low', 'info'}
        for pat in SECRET_PATTERNS:
            assert pat['severity'] in valid, (
                f'Pattern {pat["name"]} has invalid severity: {pat["severity"]}'
            )

    def test_severity_distribution(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        counts = {}
        for pat in SECRET_PATTERNS:
            counts[pat['severity']] = counts.get(pat['severity'], 0) + 1
        # Should have at least some patterns in each major severity
        assert counts.get('critical', 0) >= 20, 'Need at least 20 critical patterns'
        assert counts.get('high', 0) >= 30, 'Need at least 30 high patterns'

    def test_cwe_format(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        cwe_re = re.compile(r'^CWE-\d+$')
        for pat in SECRET_PATTERNS:
            assert cwe_re.match(pat['cwe']), (
                f'Pattern {pat["name"]} has bad CWE: {pat["cwe"]}'
            )

    def test_no_duplicate_names(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        names = [p['name'] for p in SECRET_PATTERNS]
        # Allow some near-duplicates (e.g. SSH RSA Private Key vs RSA Private Key)
        # but flag exact duplicates
        seen = set()
        for name in names:
            assert name not in seen, f'Duplicate pattern name: {name}'
            seen.add(name)

    def test_get_patterns_by_severity(self):
        from apps.scanning.engine.secrets.patterns import get_patterns_by_severity
        critical = get_patterns_by_severity('critical')
        assert all(p['severity'] == 'critical' for p in critical)
        assert len(critical) >= 20

    def test_get_critical_patterns(self):
        from apps.scanning.engine.secrets.patterns import get_critical_patterns
        critical = get_critical_patterns()
        assert all(p['severity'] == 'critical' for p in critical)

    # --- Individual pattern matching tests ---

    def test_matches_aws_access_key(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'AWS Access Key ID')
        assert pat['regex'].search('credentials: AKIAIOSFODNN7EXAMPLE')
        assert not pat['regex'].search('not_a_key_AKIAIOSFOD')

    def test_matches_stripe_secret_key(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'Stripe Secret Key')
        assert pat['regex'].search('sk_li' + 've_4eC39HqLyjWDarjtT1zdp7dc')

    def test_matches_github_pat(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'GitHub Personal Access Token')
        assert pat['regex'].search('ghp_ABCDEFabcdef1234567890abcdef12345678')

    def test_matches_rsa_private_key(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'RSA Private Key')
        assert pat['regex'].search('-----BEGIN RSA PRIVATE KEY-----')

    def test_matches_jwt_token(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'JWT Token')
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        assert pat['regex'].search(token)

    def test_matches_mongodb_connection(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'MongoDB Connection String')
        assert pat['regex'].search('mongodb+srv://user:pass@cluster0.abc.mongodb.net/db')

    def test_matches_slack_bot_token(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'Slack Bot Token')
        assert pat['regex'].search('xo' + 'xb-1234567890-1234567890123-ABCDefghIJKLmnopQRSTuvwx')

    def test_matches_sendgrid_api_key(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'SendGrid API Key')
        assert pat['regex'].search('SG' + '.abc123def456ghi789jkl0.ABCDEFghijklmnopQRSTUVWXYZ01234567890abcdef')

    def test_matches_azure_connection_string(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'Azure Storage Connection String')
        conn = 'DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=' + 'A' * 86 + '==;'
        assert pat['regex'].search(conn)

    def test_matches_password_in_url(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'Password in URL')
        assert pat['regex'].search('https://admin:SuperSecret123@db.example.com/mydb')

    def test_matches_gcp_api_key(self):
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        pat = next(p for p in SECRET_PATTERNS if p['name'] == 'GCP API Key')
        assert pat['regex'].search('AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe')


# ===========================================================================
# 2. SecretScanner Tests
# ===========================================================================
class TestSecretScanner:
    """Tests for secrets.secret_scanner.SecretScanner."""

    def setup_method(self):
        from apps.scanning.engine.secrets.secret_scanner import SecretScanner
        self.scanner = SecretScanner()

    def test_empty_page_returns_no_findings(self):
        page = _Page(body='')
        result = self.scanner.scan_pages([page])
        assert result.findings == []
        assert result.pages_scanned == 1

    def test_detects_aws_key_in_body(self):
        page = _Page(
            url='https://example.com/config.js',
            body='var awsKey = "AKIAIOSFODNN7EXAMPLE"; var region = "us-east-1";'
        )
        result = self.scanner.scan_pages([page])
        names = [f.pattern_name for f in result.findings]
        assert any('AWS' in n for n in names)

    def test_detects_stripe_key(self):
        page = _Page(
            body='const stripe = require("stripe")("' + 'sk_li' + 've_4eC39HqLyjWDarjtT1zdp7dc");'
        )
        result = self.scanner.scan_pages([page])
        names = [f.pattern_name for f in result.findings]
        assert any('Stripe' in n for n in names)

    def test_detects_private_key(self):
        page = _Page(body='-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...\n-----END RSA PRIVATE KEY-----')
        result = self.scanner.scan_pages([page])
        names = [f.pattern_name for f in result.findings]
        assert any('Private Key' in n for n in names)

    def test_detects_jwt(self):
        jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        page = _Page(body=f'Authorization: Bearer {jwt_token}')
        result = self.scanner.scan_pages([page])
        names = [f.pattern_name for f in result.findings]
        assert any('JWT' in n for n in names)

    def test_detects_github_token(self):
        page = _Page(
            body='github_token = "ghp_ABCDEFabcdef1234567890abcdef12345678"'
        )
        result = self.scanner.scan_pages([page])
        names = [f.pattern_name for f in result.findings]
        assert any('GitHub' in n for n in names)

    def test_dedup_across_pages(self):
        """Same secret on two pages should appear only once."""
        body = 'const key = "AKIAIOSFODNN7EXAMPLE";'
        pages = [
            _Page(url='https://example.com/page1', body=body),
            _Page(url='https://example.com/page1', body=body),
        ]
        result = self.scanner.scan_pages(pages)
        aws_findings = [f for f in result.findings if 'AWS' in f.pattern_name]
        assert len(aws_findings) == 1

    def test_max_findings_cap(self):
        from apps.scanning.engine.secrets.secret_scanner import SecretScanner
        scanner = SecretScanner(max_findings=3)
        body = (
            'AKIAIOSFODNN7EXAMPLE\n'
            + ('sk_li' + 've_4eC39HqLyjWDarjtT1zdp7dc\n')
            + '-----BEGIN RSA PRIVATE KEY-----\n'
            + 'ghp_ABCDEFabcdef1234567890abcdef123456\n'
            + ('xo' + 'xb-1234567890-1234567890123-ABCDefghIJKLmnopQRSTuvwx\n')
            + ('SG' + '.abc123def456ghi789jkl0.ABCDEFghijklmnopQRSTUVWXYZ012345678901234\n')
        )
        page = _Page(body=body)
        result = scanner.scan_pages([page])
        assert len(result.findings) <= 3

    def test_redact_hides_middle(self):
        from apps.scanning.engine.secrets.secret_scanner import SecretScanner
        redacted = SecretScanner._redact('AKIAIOSFODNN7EXAMPLE')
        assert redacted.startswith('AKIAIO')
        assert redacted.endswith('MPLE')
        assert '*' in redacted
        assert len(redacted) == len('AKIAIOSFODNN7EXAMPLE')

    def test_redact_short_string(self):
        from apps.scanning.engine.secrets.secret_scanner import SecretScanner
        redacted = SecretScanner._redact('short')
        assert redacted.startswith('sho')
        assert '*' in redacted

    def test_entropy_detection(self):
        """A high-entropy string near a 'secret' keyword should be flagged."""
        page = _Page(
            body='api_key = "aB3xR9mK2pQ7wY5nL1cF4hJ8vT6dU0sE"'
        )
        result = self.scanner.scan_pages([page])
        # Should detect via either pattern or entropy
        assert len(result.findings) >= 1

    def test_shannon_entropy(self):
        from apps.scanning.engine.secrets.secret_scanner import shannon_entropy
        # Known entropy: uniform distribution over 2 symbols = 1.0
        assert abs(shannon_entropy('aaabbb') - 1.0) < 0.01
        # High entropy random string
        high = shannon_entropy('aB3xR9mK2pQ7wY5nL1cF')
        assert high > 4.0
        # Low entropy
        low = shannon_entropy('aaaaaaaaaaaaaaaaaa')
        assert low < 0.1
        # Empty
        assert shannon_entropy('') == 0.0

    def test_source_map_tracking(self):
        page = _Page(
            url='https://example.com/app.js',
            body='var x = 1;\n//# sourceMappingURL=app.js.map'
        )
        result = self.scanner.scan_pages([page])
        assert len(result.source_maps_found) >= 1
        assert any('app.js.map' in url for url in result.source_maps_found)

    def test_findings_to_vulns(self):
        page = _Page(
            body='secret = "AKIAIOSFODNN7EXAMPLE";'
        )
        result = self.scanner.scan_pages([page])
        vulns = self.scanner.findings_to_vulns(result, 'https://example.com')
        assert len(vulns) >= 1
        vuln = vulns[0]
        assert 'name' in vuln
        assert 'severity' in vuln
        assert 'category' in vuln
        assert vuln['category'] == 'Secret Exposure'
        assert 'description' in vuln
        assert 'impact' in vuln
        assert 'remediation' in vuln
        assert 'cwe' in vuln
        assert 'cvss' in vuln
        assert isinstance(vuln['cvss'], float)
        assert 'affected_url' in vuln
        assert 'evidence' in vuln

    def test_multiple_secrets_on_one_page(self):
        page = _Page(
            url='https://example.com/config',
            body=(
                'aws_key = "AKIAIOSFODNN7EXAMPLE";\n'
                + 'stripe_key = "' + 'sk_li' + 've_4eC39HqLyjWDarjtT1zdp7dc";\n'
                '-----BEGIN RSA PRIVATE KEY-----\n'
                'MIIBogIBAAJ...\n'
                '-----END RSA PRIVATE KEY-----\n'
            )
        )
        result = self.scanner.scan_pages([page])
        assert len(result.findings) >= 3

    def test_finding_has_line_number(self):
        page = _Page(
            body='line1\nline2\nline3\nAKIAIOSFODNN7EXAMPLE\nline5'
        )
        result = self.scanner.scan_pages([page])
        aws_findings = [f for f in result.findings if 'AWS' in f.pattern_name]
        if aws_findings:
            assert aws_findings[0].line_number == 4

    def test_finding_has_context(self):
        page = _Page(
            body='some context before AKIAIOSFODNN7EXAMPLE some context after'
        )
        result = self.scanner.scan_pages([page])
        if result.findings:
            assert len(result.findings[0].context) > 0

    def test_scan_error_handling(self):
        """Scanner should handle broken pages gracefully."""
        bad_page = MagicMock()
        bad_page.url = 'https://example.com/bad'
        bad_page.body = property(lambda s: (_ for _ in ()).throw(RuntimeError('test')))
        type(bad_page).body = PropertyMock(side_effect=RuntimeError('test'))
        result = self.scanner.scan_pages([bad_page])
        assert len(result.errors) >= 1

    def test_base64_encoded_secret_detection(self):
        """Should detect a secret hidden in base64."""
        import base64
        # Embed an AWS key in a longer payload so the base64 blob exceeds 40 chars
        secret = 'access_key_id=AKIAIOSFODNN7EXAMPLE&secret=padding'
        encoded = base64.b64encode(secret.encode()).decode()
        page = _Page(
            body=f'config = "{encoded}"'
        )
        result = self.scanner.scan_pages([page])
        # Should find either via direct pattern or base64 decode
        assert result.base64_secrets_found >= 1 or len(result.findings) >= 1

    def test_severity_to_cvss(self):
        from apps.scanning.engine.secrets.secret_scanner import _severity_to_cvss
        assert _severity_to_cvss('critical') == 9.5
        assert _severity_to_cvss('high') == 7.5
        assert _severity_to_cvss('medium') == 5.5
        assert _severity_to_cvss('low') == 3.0
        assert _severity_to_cvss('info') == 1.0
        assert _severity_to_cvss('unknown') == 5.0

    def test_secret_finding_signature(self):
        from apps.scanning.engine.secrets.secret_scanner import SecretFinding
        f1 = SecretFinding(
            pattern_name='Test', matched_text='abc123',
            severity='high', cwe='CWE-798',
            description='test', source_url='https://example.com'
        )
        f2 = SecretFinding(
            pattern_name='Test', matched_text='abc123',
            severity='high', cwe='CWE-798',
            description='test', source_url='https://example.com'
        )
        assert f1.signature == f2.signature
        f3 = SecretFinding(
            pattern_name='Other', matched_text='abc123',
            severity='high', cwe='CWE-798',
            description='test', source_url='https://example.com'
        )
        assert f1.signature != f3.signature


# ===========================================================================
# 3. GitDumper Tests
# ===========================================================================
class TestGitDumper:
    """Tests for secrets.git_dumper.GitDumper."""

    def setup_method(self):
        from apps.scanning.engine.secrets.git_dumper import GitDumper
        self.dumper = GitDumper()

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_not_exposed_returns_empty(self, mock_fetch):
        mock_fetch.return_value = None
        result = self.dumper.check_and_dump('https://example.com')
        assert result.is_exposed is False
        assert result.extracted_secrets == []

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_detects_git_exposure(self, mock_fetch):
        def _side_effect(url):
            if '.git/HEAD' in url:
                return 'ref: refs/heads/main\n'
            if '.git/config' in url:
                return '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/user/repo.git\n'
            return None

        mock_fetch.side_effect = _side_effect
        result = self.dumper.check_and_dump('https://example.com')
        assert result.is_exposed is True
        assert '.git/HEAD' in result.accessible_paths

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_extracts_remote_url(self, mock_fetch):
        def _side_effect(url):
            if '.git/HEAD' in url:
                return 'ref: refs/heads/main\n'
            if '.git/config' in url:
                return '[remote "origin"]\n\turl = git@github.com:user/repo.git\n'
            return None

        mock_fetch.side_effect = _side_effect
        result = self.dumper.check_and_dump('https://example.com')
        assert 'git@github.com:user/repo.git' in result.remote_urls

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_extracts_branch_names(self, mock_fetch):
        def _side_effect(url):
            if '.git/HEAD' in url:
                return 'ref: refs/heads/main\n'
            if '.git/refs/heads/main' in url:
                return 'abc123def456abc123def456abc123def456abc123'
            if '.git/refs/heads/master' in url:
                return 'def456abc123def456abc123def456abc123def456'
            return None

        mock_fetch.side_effect = _side_effect
        result = self.dumper.check_and_dump('https://example.com')
        assert 'main' in result.branch_names

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_extracts_commit_messages(self, mock_fetch):
        def _side_effect(url):
            if '.git/HEAD' in url:
                return 'ref: refs/heads/main\n'
            if '.git/logs/HEAD' in url:
                return (
                    '0000 abc123 Author <a@b.com> 1234567890 +0000\tcommit: Initial commit\n'
                    'abc123 def456 Author <a@b.com> 1234567891 +0000\tcommit: Add feature\n'
                )
            return None

        mock_fetch.side_effect = _side_effect
        result = self.dumper.check_and_dump('https://example.com')
        assert any('Initial commit' in msg for msg in result.commit_messages)

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_finds_secrets_in_git_config(self, mock_fetch):
        def _side_effect(url):
            if '.git/HEAD' in url:
                return 'ref: refs/heads/main\n'
            if '.git/config' in url:
                return (
                    '[core]\n\trepositoryformatversion = 0\n'
                    'password = "' + 'sk_li' + 've_4eC39HqLyjWDarjtT1zdp7dc"\n'
                )
            return None

        mock_fetch.side_effect = _side_effect
        result = self.dumper.check_and_dump('https://example.com')
        assert len(result.extracted_secrets) >= 1

    def test_html_response_filtered(self):
        """An HTML error page should not be treated as .git content."""
        from apps.scanning.engine.secrets.git_dumper import GitDumper
        dumper = GitDumper()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>404 Not Found</body></html>'

        with patch.object(dumper.session, 'get', return_value=mock_resp):
            content = dumper._fetch('https://example.com/.git/HEAD')
            assert content is None  # HTML filtered out

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_findings_to_vulns_format(self, mock_fetch):
        def _side_effect(url):
            if '.git/HEAD' in url:
                return 'ref: refs/heads/main\n'
            return None

        mock_fetch.side_effect = _side_effect
        result = self.dumper.check_and_dump('https://example.com')

        vulns = self.dumper.findings_to_vulns(result, 'https://example.com')
        assert len(vulns) >= 1
        vuln = vulns[0]
        assert vuln['name'] == 'Exposed .git Directory'
        assert vuln['severity'] == 'high'
        assert 'cwe' in vuln
        assert 'cvss' in vuln
        assert isinstance(vuln['cvss'], float)
        assert 'affected_url' in vuln
        assert 'evidence' in vuln
        assert 'remediation' in vuln

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_not_exposed_returns_no_vulns(self, mock_fetch):
        mock_fetch.return_value = None
        result = self.dumper.check_and_dump('https://example.com')
        vulns = self.dumper.findings_to_vulns(result, 'https://example.com')
        assert vulns == []

    @patch('apps.scanning.engine.secrets.git_dumper.GitDumper._fetch')
    def test_packed_refs_extracts_branches(self, mock_fetch):
        def _side_effect(url):
            if '.git/HEAD' in url:
                return 'ref: refs/heads/main\n'
            if '.git/packed-refs' in url:
                return (
                    '# pack-refs with: peeled fully-peeled sorted\n'
                    'abc123def456abc123def456abc123def456abc123 refs/heads/develop\n'
                    'def456abc123def456abc123def456abc123def456 refs/heads/feature\n'
                )
            return None

        mock_fetch.side_effect = _side_effect
        result = self.dumper.check_and_dump('https://example.com')
        assert 'develop' in result.branch_names
        assert 'feature' in result.branch_names

    def test_object_url_format(self):
        from apps.scanning.engine.secrets.git_dumper import GitDumper
        url = GitDumper._object_url('https://example.com/', 'abc123def456abc123def456abc123def456abc123')
        assert url == 'https://example.com/.git/objects/ab/c123def456abc123def456abc123def456abc123'

    def test_git_dump_result_defaults(self):
        from apps.scanning.engine.secrets.git_dumper import GitDumpResult
        r = GitDumpResult()
        assert r.is_exposed is False
        assert r.accessible_paths == []
        assert r.extracted_secrets == []
        assert r.sensitive_files_found == []
        assert r.commit_messages == []
        assert r.branch_names == []
        assert r.remote_urls == []
        assert r.errors == []


# ===========================================================================
# 4. SecretScanResult Tests
# ===========================================================================
class TestSecretScanResult:
    """Tests for data classes."""

    def test_result_defaults(self):
        from apps.scanning.engine.secrets.secret_scanner import SecretScanResult
        r = SecretScanResult()
        assert r.findings == []
        assert r.pages_scanned == 0
        assert r.patterns_matched == 0
        assert r.entropy_detections == 0
        assert r.source_maps_found == []
        assert r.base64_secrets_found == 0
        assert r.errors == []

    def test_finding_defaults(self):
        from apps.scanning.engine.secrets.secret_scanner import SecretFinding
        f = SecretFinding(
            pattern_name='Test', matched_text='value',
            severity='high', cwe='CWE-798',
            description='d', source_url='https://example.com'
        )
        assert f.line_number == 0
        assert f.context == ''
        assert f.entropy == 0.0
        assert f.is_entropy_based is False
        assert f.confidence == 'high'


# ===========================================================================
# 5. Integration Tests
# ===========================================================================
class TestSecretScannerIntegration:
    """Integration tests: imports, orchestrator wiring."""

    def test_imports(self):
        from apps.scanning.engine.secrets import secret_scanner
        from apps.scanning.engine.secrets import patterns
        from apps.scanning.engine.secrets import git_dumper
        assert hasattr(secret_scanner, 'SecretScanner')
        assert hasattr(patterns, 'SECRET_PATTERNS')
        assert hasattr(git_dumper, 'GitDumper')

    def test_scanner_accepts_mock_pages(self):
        from apps.scanning.engine.secrets.secret_scanner import SecretScanner
        from tests.conftest import MockPage
        scanner = SecretScanner()
        page = MockPage(url='https://example.com', body='nothing here')
        result = scanner.scan_pages([page])
        assert result.pages_scanned == 1

    def test_vuln_dict_compatible_with_orchestrator(self):
        """Vuln dicts should have all keys the orchestrator expects."""
        from apps.scanning.engine.secrets.secret_scanner import SecretScanner
        scanner = SecretScanner()
        page = _Page(body='AKIAIOSFODNN7EXAMPLE')
        result = scanner.scan_pages([page])
        vulns = scanner.findings_to_vulns(result)
        required_keys = {'name', 'severity', 'category', 'description',
                         'impact', 'remediation', 'cwe', 'cvss',
                         'affected_url', 'evidence'}
        for v in vulns:
            assert required_keys.issubset(v.keys()), f'Missing keys: {required_keys - v.keys()}'

    def test_git_vulns_compatible(self):
        from apps.scanning.engine.secrets.git_dumper import GitDumper, GitDumpResult
        dumper = GitDumper()
        fake = GitDumpResult(
            is_exposed=True,
            accessible_paths=['.git/HEAD', '.git/config'],
        )
        vulns = dumper.findings_to_vulns(fake, 'https://example.com')
        required_keys = {'name', 'severity', 'category', 'description',
                         'impact', 'remediation', 'cwe', 'cvss',
                         'affected_url', 'evidence'}
        for v in vulns:
            assert required_keys.issubset(v.keys())

    def test_pattern_matches_do_not_throw(self):
        """All patterns should match against random long text without errors."""
        from apps.scanning.engine.secrets.patterns import SECRET_PATTERNS
        test_text = 'a' * 10000 + 'AKIAIOSFODNN7EXAMPLE' + 'b' * 10000
        for pat in SECRET_PATTERNS:
            # Should not raise
            list(pat['regex'].finditer(test_text))
