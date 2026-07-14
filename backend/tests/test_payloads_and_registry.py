"""Tests for the payload modules."""


class TestSQLiPayloads:
    def test_payloads_not_empty(self):
        from apps.scanning.engine.payloads.sqli_payloads import ERROR_BASED, BOOLEAN_BLIND, TIME_BLIND_MYSQL
        assert len(ERROR_BASED) > 0
        assert len(BOOLEAN_BLIND) > 0
        assert len(TIME_BLIND_MYSQL) > 0

    def test_error_patterns_exist(self):
        from apps.scanning.engine.payloads.sqli_payloads import SQLI_ERROR_PATTERNS
        assert len(SQLI_ERROR_PATTERNS) > 0

    def test_waf_signatures_exist(self):
        from apps.scanning.engine.payloads.sqli_payloads import WAF_SIGNATURES
        assert len(WAF_SIGNATURES) > 0


class TestXSSPayloads:
    def test_payloads_not_empty(self):
        from apps.scanning.engine.payloads.xss_payloads import BASIC_REFLECTED, POLYGLOTS
        assert len(BASIC_REFLECTED) > 0
        assert len(POLYGLOTS) > 0

    def test_dom_sources_sinks(self):
        from apps.scanning.engine.payloads.xss_payloads import DOM_SOURCES, DOM_SINKS
        assert len(DOM_SOURCES) > 0
        assert len(DOM_SINKS) > 0

    def test_canary_defined(self):
        from apps.scanning.engine.payloads.xss_payloads import CANARY
        assert isinstance(CANARY, str)
        assert len(CANARY) > 5


class TestSSTIPayloads:
    def test_engine_payloads(self):
        from apps.scanning.engine.payloads.ssti_payloads import GENERIC_DETECTION, ENGINE_INDICATORS
        assert len(GENERIC_DETECTION) > 0
        assert len(ENGINE_INDICATORS) > 0


class TestSSRFPayloads:
    def test_payloads_not_empty(self):
        from apps.scanning.engine.payloads.ssrf_payloads import BASIC_INTERNAL, AWS_METADATA
        assert len(BASIC_INTERNAL) > 0
        assert len(AWS_METADATA) > 0


class TestXXEPayloads:
    def test_payloads_not_empty(self):
        from apps.scanning.engine.payloads.xxe_payloads import CLASSIC_XXE, BLIND_OOB
        assert len(CLASSIC_XXE) > 0
        assert len(BLIND_OOB) > 0


class TestCMDiPayloads:
    def test_payloads_not_empty(self):
        from apps.scanning.engine.payloads.cmdi_payloads import BASH_PAYLOADS, WINDOWS_PAYLOADS
        assert len(BASH_PAYLOADS) > 0
        assert len(WINDOWS_PAYLOADS) > 0


class TestTraversalPayloads:
    def test_payloads_not_empty(self):
        from apps.scanning.engine.payloads.traversal_payloads import BASIC_UNIX, BASIC_WINDOWS
        assert len(BASIC_UNIX) > 0
        assert len(BASIC_WINDOWS) > 0


class TestNoSQLPayloads:
    def test_payloads_not_empty(self):
        from apps.scanning.engine.payloads.nosql_payloads import MONGO_OPERATORS, URL_PARAM_INJECTION
        assert len(MONGO_OPERATORS) > 0
        assert len(URL_PARAM_INJECTION) > 0


class TestDefaultCredentials:
    def test_credentials_not_empty(self):
        from apps.scanning.engine.payloads.default_credentials import GENERIC_ADMIN, CMS_DEFAULTS
        assert len(GENERIC_ADMIN) > 0
        assert len(CMS_DEFAULTS) > 0


class TestSensitivePaths:
    def test_paths_not_empty(self):
        from apps.scanning.engine.payloads.sensitive_paths import ALL_PATHS
        assert len(ALL_PATHS) > 0
        # All paths should start with /
        for path in ALL_PATHS[:20]:
            assert path.startswith('/'), f'Path does not start with /: {path}'


class TestFuzzVectors:
    def test_vectors_not_empty(self):
        from apps.scanning.engine.payloads.fuzz_vectors import BOUNDARY_VALUES, SPECIAL_CHARS
        assert len(BOUNDARY_VALUES) > 0
        assert len(SPECIAL_CHARS) > 0


class TestNewXSSPayloads:
    def test_mutation_xss_not_empty(self):
        from apps.scanning.engine.payloads.xss_payloads import MUTATION_XSS
        assert len(MUTATION_XSS) > 0

    def test_csp_bypass_not_empty(self):
        from apps.scanning.engine.payloads.xss_payloads import CSP_BYPASS
        assert len(CSP_BYPASS) > 0

    def test_dom_clobbering_not_empty(self):
        from apps.scanning.engine.payloads.xss_payloads import DOM_CLOBBERING
        assert len(DOM_CLOBBERING) > 0

    def test_all_payloads_includes_new(self):
        from apps.scanning.engine.payloads.xss_payloads import get_all_xss_payloads, MUTATION_XSS, CSP_BYPASS
        all_p = get_all_xss_payloads()
        for p in MUTATION_XSS[:3]:
            assert p in all_p
        for p in CSP_BYPASS[:3]:
            assert p in all_p


class TestNewSQLiPayloads:
    def test_stacked_queries_not_empty(self):
        from apps.scanning.engine.payloads.sqli_payloads import STACKED_QUERIES
        assert len(STACKED_QUERIES) > 0

    def test_second_order_not_empty(self):
        from apps.scanning.engine.payloads.sqli_payloads import SECOND_ORDER
        assert len(SECOND_ORDER) > 0

    def test_nosql_injection_not_empty(self):
        from apps.scanning.engine.payloads.sqli_payloads import NOSQL_INJECTION
        assert len(NOSQL_INJECTION) > 0

    def test_get_nosql_payloads(self):
        from apps.scanning.engine.payloads.sqli_payloads import get_nosql_payloads
        payloads = get_nosql_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0


class TestNewCMDiPayloads:
    def test_oob_payloads_not_empty(self):
        from apps.scanning.engine.payloads.cmdi_payloads import OOB_PAYLOADS
        assert len(OOB_PAYLOADS) > 0

    def test_info_payloads_not_empty(self):
        from apps.scanning.engine.payloads.cmdi_payloads import INFO_PAYLOADS
        assert len(INFO_PAYLOADS) > 0

    def test_all_payloads_includes_new(self):
        from apps.scanning.engine.payloads.cmdi_payloads import get_all_cmdi_payloads, OOB_PAYLOADS
        all_p = get_all_cmdi_payloads()
        for p in OOB_PAYLOADS[:3]:
            assert p in all_p


class TestPromptInjectionPayloads:
    def test_payloads_importable(self):
        from apps.scanning.engine.payloads.prompt_injection_payloads import (
            DIRECT_INJECTION, JAILBREAK_PROMPTS
        )
        assert len(DIRECT_INJECTION) > 0
        assert len(JAILBREAK_PROMPTS) > 0


class TestTesterRegistry:
    def test_get_all_testers(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert len(testers) >= 35  # We have 35 testers now

    def test_all_testers_have_test_method(self):
        from apps.scanning.engine.testers import get_all_testers
        for tester in get_all_testers():
            assert hasattr(tester, 'test'), f'{tester.__class__.__name__} missing test()'

    def test_all_testers_have_name(self):
        from apps.scanning.engine.testers import get_all_testers
        for tester in get_all_testers():
            assert hasattr(tester, 'TESTER_NAME'), f'{tester.__class__.__name__} missing TESTER_NAME'
            assert tester.TESTER_NAME != 'Base', f'{tester.__class__.__name__} has default name'

    def test_no_duplicate_names(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert len(names) == len(set(names)), f'Duplicate tester names: {names}'

    def test_all_testers_accept_recon_data(self):
        """All testers should accept the recon_data kwarg."""
        import inspect
        from apps.scanning.engine.testers import get_all_testers
        for tester in get_all_testers():
            sig = inspect.signature(tester.test)
            params = list(sig.parameters.keys())
            assert 'recon_data' in params, f'{tester.TESTER_NAME} missing recon_data parameter'
