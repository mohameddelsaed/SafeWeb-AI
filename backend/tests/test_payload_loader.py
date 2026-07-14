"""Tests for Phase 22 — Payload Loader & Mega Wordlist Library."""
import os


# ── PayloadLoader Tests ─────────────────────────────────────────────────────

class TestPayloadLoaderInit:
    """Test PayloadLoader initialisation and basic attributes."""

    def test_default_data_dir_exists(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader, _DATA_DIR
        assert os.path.isdir(_DATA_DIR)
        loader = PayloadLoader()
        assert loader._data_dir == _DATA_DIR

    def test_custom_data_dir(self, tmp_path):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader(data_dir=str(tmp_path))
        assert loader._data_dir == str(tmp_path)

    def test_available_types(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        types_ = loader.get_available_types()
        expected = ['sqli', 'xss', 'cmdi', 'ssti', 'ssrf', 'traversal',
                    'xxe', 'nosql', 'open_redirect']
        for t in expected:
            assert t in types_, f'Missing type: {t}'


class TestPayloadLoaderLazyLoad:
    """Test lazy loading from text files."""

    def test_sqli_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('sqli', depth='shallow')
        assert len(payloads) > 0
        assert len(payloads) <= 100  # shallow limit

    def test_xss_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('xss', depth='shallow')
        assert len(payloads) > 0
        assert len(payloads) <= 100

    def test_cmdi_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('cmdi', depth='shallow')
        assert len(payloads) > 0

    def test_ssti_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('ssti', depth='medium')
        assert len(payloads) > 0

    def test_ssrf_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('ssrf', depth='shallow')
        assert len(payloads) > 0

    def test_traversal_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('traversal', depth='medium')
        assert len(payloads) > 0

    def test_xxe_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('xxe', depth='deep')
        assert len(payloads) > 0

    def test_nosql_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('nosql', depth='medium')
        assert len(payloads) > 0

    def test_open_redirect_payloads_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('open_redirect', depth='medium')
        assert len(payloads) > 0

    def test_unknown_type_returns_empty(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('nonexistent_type')
        assert payloads == []

    def test_comments_and_blanks_stripped(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('sqli', depth='deep')
        for p in payloads:
            assert not p.startswith('#'), f'Comment not stripped: {p}'
            assert len(p.strip()) > 0, 'Blank line not stripped'


class TestPayloadDepthFiltering:
    """Test depth controls: shallow=100, medium=1000, deep=all."""

    def test_shallow_limit(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        shallow = loader.get_payloads('sqli', depth='shallow')
        assert len(shallow) <= 100

    def test_medium_limit(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        medium = loader.get_payloads('sqli', depth='medium')
        assert len(medium) <= 1000

    def test_deep_returns_all(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        deep = loader.get_payloads('sqli', depth='deep')
        total = loader.get_payload_count('sqli')
        assert len(deep) == total

    def test_depth_ordering(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        shallow = loader.get_payloads('xss', depth='shallow')
        medium = loader.get_payloads('xss', depth='medium')
        deep = loader.get_payloads('xss', depth='deep')
        assert len(shallow) <= len(medium) <= len(deep)

    def test_shallow_is_prefix_of_medium(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        shallow = loader.get_payloads('cmdi', depth='shallow')
        medium = loader.get_payloads('cmdi', depth='medium')
        # shallow should be a prefix of medium
        for i, p in enumerate(shallow):
            assert p == medium[i], f'Mismatch at index {i}'


class TestPayloadWafFiltering:
    """Test WAF-specific payload loading."""

    def test_cloudflare_sqli_tamper(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('sqli', depth='deep', waf='cloudflare')
        no_waf = loader.get_payloads('sqli', depth='deep')
        # WAF payloads should add more than base
        assert len(payloads) > len(no_waf)

    def test_modsecurity_sqli_tamper(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('sqli', depth='deep', waf='modsecurity')
        no_waf = loader.get_payloads('sqli', depth='deep')
        assert len(payloads) > len(no_waf)

    def test_waf_name_normalization(self):
        from apps.scanning.engine.payloads.payload_loader import WAF_NAME_MAP
        assert WAF_NAME_MAP['cloudflare'] == 'cloudflare'
        assert WAF_NAME_MAP['mod_security'] == 'modsecurity'
        assert WAF_NAME_MAP['incapsula'] == 'imperva'
        assert WAF_NAME_MAP['aws waf'] == 'aws_waf'

    def test_generic_waf_bypass_files_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        # Loading XSS with a known WAF should try waf_bypass dir
        payloads = loader.get_payloads('xss', depth='deep', waf='cloudflare')
        assert len(payloads) > 0


class TestPayloadTechFiltering:
    """Test technology-specific payload filtering."""

    def test_ssti_python_loads_jinja2(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('ssti', depth='deep', tech='python')
        # Should include Jinja2-specific payloads
        has_jinja = any('__class__' in p or 'config' in p for p in payloads)
        assert has_jinja

    def test_ssti_php_loads_twig(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('ssti', depth='deep', tech='php')
        # Should include Twig payloads
        has_twig = any('filter' in p or 'dump' in p for p in payloads)
        assert has_twig

    def test_ssti_no_tech_loads_all(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        all_ssti = loader.get_payloads('ssti', depth='deep')
        python_ssti = loader.get_payloads('ssti', depth='deep', tech='python')
        # Without tech filter, should get more or equal payloads
        assert len(all_ssti) >= len(python_ssti)


class TestPayloadContextSelection:
    """Test context-aware payload selection."""

    def test_xss_html_attr_context(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('xss', context='html_attr', depth='deep')
        assert len(payloads) > 0
        # Should include attribute-context payloads
        has_attr = any('onload' in p.lower() or 'onfocus' in p.lower()
                       or 'onerror' in p.lower() for p in payloads)
        assert has_attr

    def test_xss_js_string_context(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('xss', context='js_string', depth='deep')
        assert len(payloads) > 0

    def test_xss_svg_math_context(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.get_payloads('xss', context='svg_math', depth='deep')
        assert len(payloads) > 0
        has_svg = any('<svg' in p.lower() or '<math' in p.lower() for p in payloads)
        assert has_svg

    def test_context_plus_main_files(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        # Context payloads should come first, then main files
        ctx_payloads = loader.get_payloads('xss', context='html_attr', depth='deep')
        main_payloads = loader.get_payloads('xss', depth='deep')
        # Context variant should have both context + main payloads
        assert len(ctx_payloads) > len(main_payloads)


class TestPayloadFileFormat:
    """Test payload file format and content quality."""

    def test_sqli_files_have_sql_keywords(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.load_file('sqli/error_based.txt')
        assert len(payloads) > 50
        has_sql = any(kw in ' '.join(payloads).upper()
                      for kw in ['SELECT', 'UNION', 'OR', 'AND', "'"])
        assert has_sql

    def test_xss_files_have_script_tags(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.load_file('xss/reflected.txt')
        assert len(payloads) > 50
        has_xss = any('<script' in p.lower() or 'alert' in p.lower()
                      for p in payloads)
        assert has_xss

    def test_xxe_files_have_entity_declarations(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.load_file('xxe/inband.txt')
        assert len(payloads) > 5
        has_xxe = any('ENTITY' in p or 'DOCTYPE' in p for p in payloads)
        assert has_xxe

    def test_traversal_has_dot_dot_slash(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        payloads = loader.load_file('traversal/unix.txt')
        has_traversal = any('../' in p for p in payloads)
        assert has_traversal


class TestPayloadCount:
    """Test total payload counts meet professional thresholds."""

    def test_sqli_payload_count(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        count = loader.get_payload_count('sqli')
        assert count >= 200, f'SQLi payloads only {count}, need 200+'

    def test_xss_payload_count(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        count = loader.get_payload_count('xss')
        assert count >= 150, f'XSS payloads only {count}, need 150+'

    def test_cmdi_payload_count(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        count = loader.get_payload_count('cmdi')
        assert count >= 50, f'CMDi payloads only {count}, need 50+'

    def test_ssrf_payload_count(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        count = loader.get_payload_count('ssrf')
        assert count >= 50, f'SSRF payloads only {count}, need 50+'


class TestMemoryEfficiency:
    """Test generator-based lazy loading."""

    def test_iter_payloads_returns_generator(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        result = loader.iter_payloads('sqli', depth='deep')
        assert hasattr(result, '__next__'), 'iter_payloads should return a generator'

    def test_cache_works(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        # Load once to populate cache
        first = loader.load_file('sqli/error_based.txt')
        assert len(loader._cache) > 0
        # Load again — should come from cache
        second = loader.load_file('sqli/error_based.txt')
        assert first == second

    def test_clear_cache(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        loader.load_file('sqli/error_based.txt')
        assert len(loader._cache) > 0
        loader.clear_cache()
        assert len(loader._cache) == 0


class TestWordlists:
    """Test wordlist loading."""

    def test_content_common_wordlist(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        words = loader.load_wordlist('content_common')
        assert len(words) > 50
        assert 'admin' in words
        assert 'login' in words

    def test_api_routes_wordlist(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        words = loader.load_wordlist('api_routes')
        assert len(words) > 30
        assert any('/api' in w for w in words)

    def test_params_common_wordlist(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        words = loader.load_wordlist('params_common')
        assert len(words) > 30
        assert 'id' in words
        assert 'username' in words

    def test_subdomains_wordlist(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        words = loader.load_wordlist('subdomains')
        assert len(words) > 30
        assert 'www' in words
        assert 'api' in words

    def test_nonexistent_wordlist_returns_empty(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        words = loader.load_wordlist('does_not_exist')
        assert words == []


class TestSecretPatterns:
    """Test secret detection pattern loading."""

    def test_patterns_load(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        patterns = loader.load_secret_patterns()
        assert len(patterns) > 10

    def test_patterns_are_compiled(self):
        import re
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        patterns = loader.load_secret_patterns()
        for name, regex in patterns:
            assert isinstance(name, str)
            assert isinstance(regex, type(re.compile('')))

    def test_aws_key_pattern_matches(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        patterns = loader.load_secret_patterns()
        aws_patterns = [p for name, p in patterns if 'AWS_ACCESS' in name]
        assert len(aws_patterns) > 0
        # Should match dummy AWS key format
        assert aws_patterns[0].search('AKIAIOSFODNN7EXAMPLE')

    def test_github_token_pattern_matches(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        patterns = loader.load_secret_patterns()
        gh_patterns = [p for name, p in patterns if 'GITHUB_TOKEN' in name]
        assert len(gh_patterns) > 0
        assert gh_patterns[0].search('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123')


class TestModuleLevelConvenience:
    """Test module-level get_payloads() and get_loader() functions."""

    def test_get_loader_returns_singleton(self):
        from apps.scanning.engine.payloads import payload_loader
        # Reset singleton
        payload_loader._default_loader = None
        loader1 = payload_loader.get_loader()
        loader2 = payload_loader.get_loader()
        assert loader1 is loader2

    def test_module_get_payloads(self):
        from apps.scanning.engine.payloads.payload_loader import get_payloads
        payloads = get_payloads('sqli', depth='shallow')
        assert len(payloads) > 0
        assert len(payloads) <= 100


class TestPayloadEngineIntegration:
    """Test PayloadEngine integration with new loader and types."""

    def test_engine_loads_xxe(self):
        from apps.scanning.engine.payloads.payload_engine import PayloadEngine
        engine = PayloadEngine()
        payloads = engine.get_payloads('xxe', depth='deep')
        assert len(payloads) > 0

    def test_engine_loads_traversal(self):
        from apps.scanning.engine.payloads.payload_engine import PayloadEngine
        engine = PayloadEngine()
        payloads = engine.get_payloads('traversal', depth='deep')
        assert len(payloads) > 0

    def test_engine_loads_nosql(self):
        from apps.scanning.engine.payloads.payload_engine import PayloadEngine
        engine = PayloadEngine()
        payloads = engine.get_payloads('nosql', depth='deep')
        assert len(payloads) > 0

    def test_engine_loads_open_redirect(self):
        from apps.scanning.engine.payloads.payload_engine import PayloadEngine
        engine = PayloadEngine()
        payloads = engine.get_payloads('open_redirect', depth='deep')
        assert len(payloads) > 0

    def test_engine_deep_augments_with_file_payloads(self):
        from apps.scanning.engine.payloads.payload_engine import PayloadEngine
        engine = PayloadEngine()
        # Deep scan should pull from both Python modules and data/ files
        deep = engine.get_payloads('sqli', depth='deep')
        shallow = engine.get_payloads('sqli', depth='shallow')
        assert len(deep) >= len(shallow)

    def test_engine_still_works_for_existing_types(self):
        from apps.scanning.engine.payloads.payload_engine import PayloadEngine
        engine = PayloadEngine()
        for vtype in ['xss', 'sqli', 'ssrf', 'ssti', 'cmdi']:
            payloads = engine.get_payloads(vtype, depth='medium')
            assert len(payloads) > 0, f'{vtype} returned no payloads'


class TestPathTraversalSafety:
    """Ensure the loader doesn't allow path traversal attacks."""

    def test_cannot_escape_data_dir(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        # Attempting to load a file outside data/ should return empty
        result = loader.load_file('../../../../../../etc/passwd')
        assert result == []

    def test_cannot_escape_with_encoded_path(self):
        from apps.scanning.engine.payloads.payload_loader import PayloadLoader
        loader = PayloadLoader()
        result = loader.load_file('..%2f..%2f..%2fetc%2fpasswd')
        assert result == []
