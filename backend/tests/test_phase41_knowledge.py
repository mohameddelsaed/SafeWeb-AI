"""
Phase 41 — Vulnerability Knowledge Base Tests.

Tests for:
  - VulnKB             (engine/knowledge/vuln_kb.py)
  - RemediationKB      (engine/knowledge/remediation_kb.py)
  - COMPLIANCE_MAP     constant
  - VULNERABILITY_DB   constant
  - REMEDIATION_DB     constant
  - KnowledgeTester    (testers/knowledge_tester.py)
  - Package imports    (engine/knowledge/__init__.py)
  - Registration (#73)
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')
django.setup()


# ──────────────────────────────────────────────────────────────────────────────
# VulnKB — construction & basic lookup
# ──────────────────────────────────────────────────────────────────────────────

class TestVulnKBBasicLookup:
    def test_get_sqli_returns_dict(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        entry = kb.get('CWE-89')
        assert isinstance(entry, dict)

    def test_get_xss_returns_dict(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get('CWE-79') is not None

    def test_get_ssrf_returns_dict(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get('CWE-918') is not None

    def test_get_idor_returns_dict(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get('CWE-639') is not None

    def test_get_unknown_cwe_returns_none(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get('CWE-9999') is None

    def test_get_by_id_sqli(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        entry = kb.get_by_id('sqli')
        assert entry is not None
        assert entry['cwe'] == 'CWE-89'

    def test_get_by_id_xss(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get_by_id('xss') is not None

    def test_get_by_id_unknown_returns_none(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get_by_id('zzz_unknown') is None

    def test_get_by_cwe_alias(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get_by_cwe('CWE-22') == kb.get('CWE-22')


# ──────────────────────────────────────────────────────────────────────────────
# VulnKB — required fields
# ──────────────────────────────────────────────────────────────────────────────

class TestVulnKBFields:
    _REQUIRED = ('id', 'name', 'cwe', 'description', 'mitre_attack',
                 'cvss_range', 'real_world_examples', 'cve_examples',
                 'owasp_testing_guide', 'owasp_top10_2021')

    def test_all_entries_have_required_fields(self):
        from apps.scanning.engine.knowledge.vuln_kb import VULNERABILITY_DB
        for cwe, entry in VULNERABILITY_DB.items():
            for field in self._REQUIRED:
                assert field in entry, (
                    f'CWE {cwe} missing field "{field}"'
                )

    def test_mitre_attack_has_tactic_and_technique(self):
        from apps.scanning.engine.knowledge.vuln_kb import VULNERABILITY_DB
        for cwe, entry in VULNERABILITY_DB.items():
            m = entry['mitre_attack']
            assert 'tactic' in m, f'{cwe}: mitre_attack missing "tactic"'
            assert 'technique' in m, f'{cwe}: mitre_attack missing "technique"'

    def test_cvss_range_has_min_max(self):
        from apps.scanning.engine.knowledge.vuln_kb import VULNERABILITY_DB
        for cwe, entry in VULNERABILITY_DB.items():
            r = entry['cvss_range']
            assert 'min' in r and 'max' in r, f'{cwe}: cvss_range missing min/max'
            assert r['min'] <= r['max'], f'{cwe}: cvss_range min > max'

    def test_cve_examples_are_strings(self):
        from apps.scanning.engine.knowledge.vuln_kb import VULNERABILITY_DB
        for cwe, entry in VULNERABILITY_DB.items():
            for cve in entry['cve_examples']:
                assert isinstance(cve, str), f'{cwe}: CVE entry not a string'
                assert cve.startswith('CVE-'), f'{cwe}: CVE not in CVE-YYYY-N format'

    def test_owasp_testing_guide_are_strings(self):
        from apps.scanning.engine.knowledge.vuln_kb import VULNERABILITY_DB
        for cwe, entry in VULNERABILITY_DB.items():
            for ref in entry['owasp_testing_guide']:
                assert ref.startswith('WSTG-'), f'{cwe}: bad WSTG ref "{ref}"'

    def test_real_world_examples_structure(self):
        from apps.scanning.engine.knowledge.vuln_kb import VULNERABILITY_DB
        for cwe, entry in VULNERABILITY_DB.items():
            for ex in entry['real_world_examples']:
                assert 'title' in ex, f'{cwe}: example missing "title"'
                assert 'description' in ex, f'{cwe}: example missing "description"'

    def test_sqli_at_least_two_real_world_examples(self):
        from apps.scanning.engine.knowledge.vuln_kb import VULNERABILITY_DB
        assert len(VULNERABILITY_DB['CWE-89']['real_world_examples']) >= 2


# ──────────────────────────────────────────────────────────────────────────────
# VulnKB — search, all_ids, all_cwes
# ──────────────────────────────────────────────────────────────────────────────

class TestVulnKBSearch:
    def test_search_injection_finds_sqli(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        results = kb.search('injection')
        names = [r['name'] for r in results]
        assert any('SQL' in n or 'Injection' in n for n in names)

    def test_search_no_match_returns_empty(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.search('zzz_no_match_xyz') == []

    def test_search_returns_list(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        result = kb.search('request forgery')
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_all_ids_not_empty(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        ids = kb.all_ids()
        assert len(ids) >= 10

    def test_all_ids_sorted(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        ids = kb.all_ids()
        assert ids == sorted(ids)

    def test_all_cwes_at_least_10(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert len(kb.all_cwes()) >= 10

    def test_known_short_ids_present(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        for short_id in ('sqli', 'xss', 'ssrf', 'idor', 'csrf', 'rce'):
            assert short_id in kb.all_ids(), f'Missing id "{short_id}"'


# ──────────────────────────────────────────────────────────────────────────────
# VulnKB — helper methods
# ──────────────────────────────────────────────────────────────────────────────

class TestVulnKBHelpers:
    def test_get_mitre_returns_dict(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        m = kb.get_mitre('CWE-89')
        assert isinstance(m, dict)
        assert 'tactic' in m
        assert 'technique' in m

    def test_get_mitre_unknown_returns_none(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get_mitre('CWE-0000') is None

    def test_get_cve_examples_sqli_nonempty(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        cves = kb.get_cve_examples('CWE-89')
        assert len(cves) >= 1

    def test_get_cve_examples_unknown_returns_empty(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get_cve_examples('CWE-0000') == []

    def test_get_real_world_examples_returns_list(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        examples = kb.get_real_world_examples('CWE-89')
        assert isinstance(examples, list)
        assert len(examples) >= 1

    def test_get_owasp_testing_guide_returns_list(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        refs = kb.get_owasp_testing_guide('CWE-89')
        assert isinstance(refs, list)
        assert len(refs) >= 1

    def test_get_cvss_range_sqli(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        r = kb.get_cvss_range('CWE-89')
        assert r is not None
        assert r['min'] > 0
        assert r['max'] <= 10.0

    def test_get_cvss_range_unknown_returns_none(self):
        from apps.scanning.engine.knowledge.vuln_kb import VulnKB
        kb = VulnKB()
        assert kb.get_cvss_range('CWE-0000') is None


# ──────────────────────────────────────────────────────────────────────────────
# RemediationKB — basic lookup
# ──────────────────────────────────────────────────────────────────────────────

class TestRemediationKBBasic:
    def test_get_remediation_sqli(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        entry = kb.get_remediation('CWE-89')
        assert isinstance(entry, dict)
        assert 'code_fixes' in entry

    def test_get_remediation_unknown_returns_none(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.get_remediation('CWE-9999') is None

    def test_has_remediation_known_cwe(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.has_remediation('CWE-89') is True

    def test_has_remediation_unknown_cwe(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.has_remediation('CWE-9999') is False

    def test_remediation_db_covers_all_vuln_kb_cwes(self):
        """Every CWE in VulnKB should also have a remediation entry."""
        from apps.scanning.engine.knowledge.vuln_kb import VULNERABILITY_DB
        from apps.scanning.engine.knowledge.remediation_kb import REMEDIATION_DB
        for cwe in VULNERABILITY_DB:
            assert cwe in REMEDIATION_DB, (
                f'CWE {cwe} in VulnKB but missing from RemediationKB'
            )


# ──────────────────────────────────────────────────────────────────────────────
# RemediationKB — code fixes
# ──────────────────────────────────────────────────────────────────────────────

class TestRemediationKBCodeFixes:
    def test_python_code_fix_sqli_nonempty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        fix = kb.get_code_fix('CWE-89', 'python')
        assert fix is not None
        assert len(fix) > 20

    def test_nodejs_code_fix_sqli_nonempty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        fix = kb.get_code_fix('CWE-89', 'nodejs')
        assert fix is not None

    def test_python_fix_xss_nonempty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        fix = kb.get_code_fix('CWE-79', 'python')
        assert fix is not None

    def test_code_fix_unknown_cwe_returns_none(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.get_code_fix('CWE-9999', 'python') is None

    def test_code_fix_empty_snippet_returns_none(self):
        """Languages with empty snippets should return None (not empty string)."""
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        # CWE-918 has empty java/php snippets by design
        result = kb.get_code_fix('CWE-918', 'java')
        assert result is None

    def test_sql_fix_contains_parameterised_hint(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        fix = kb.get_code_fix('CWE-89', 'python')
        assert 'param' in fix.lower() or '%s' in fix or '?' in fix

    def test_java_sqli_fix_contains_preparedstatement(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        fix = kb.get_code_fix('CWE-89', 'java')
        assert 'PreparedStatement' in fix


# ──────────────────────────────────────────────────────────────────────────────
# RemediationKB — server configs & headers
# ──────────────────────────────────────────────────────────────────────────────

class TestRemediationKBServerAndHeaders:
    def test_nginx_config_sqli_nonempty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        cfg = kb.get_server_config('CWE-89', 'nginx')
        assert cfg is not None

    def test_nginx_config_xss_contains_header(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        cfg = kb.get_server_config('CWE-79', 'nginx')
        assert cfg is not None
        assert 'Content-Security-Policy' in cfg or 'X-Content-Type-Options' in cfg

    def test_server_config_unknown_cwe_returns_none(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.get_server_config('CWE-9999', 'nginx') is None

    def test_header_fixes_xss_nonempty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        headers = kb.get_header_fixes('CWE-79')
        assert isinstance(headers, list)
        assert len(headers) >= 1

    def test_header_fixes_have_required_keys(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        for cwe in ('CWE-79', 'CWE-352', 'CWE-312'):
            for h in kb.get_header_fixes(cwe):
                assert 'header' in h, f'{cwe}: header fix missing "header" key'
                assert 'value' in h, f'{cwe}: header fix missing "value" key'
                assert 'reason' in h, f'{cwe}: header fix missing "reason" key'

    def test_header_fixes_unknown_cwe_returns_empty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.get_header_fixes('CWE-9999') == []

    def test_framework_guidance_sqli_nonempty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        guidance = kb.get_framework_guidance('CWE-89')
        assert isinstance(guidance, dict)
        assert len(guidance) >= 1

    def test_framework_guidance_unknown_returns_empty_dict(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.get_framework_guidance('CWE-9999') == {}


# ──────────────────────────────────────────────────────────────────────────────
# RemediationKB — compliance mapping
# ──────────────────────────────────────────────────────────────────────────────

class TestRemediationKBCompliance:
    def test_compliance_sqli_not_none(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.get_compliance('CWE-89') is not None

    def test_compliance_xss_owasp_top10(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        compliance = kb.get_compliance('CWE-79')
        assert compliance['owasp_top10_2021'] == 'A03:2021'

    def test_compliance_sqli_pci_dss_nonempty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        controls = kb.get_compliance_for_framework('CWE-89', 'pci_dss_v4')
        assert len(controls) >= 1

    def test_compliance_broken_auth_nist_nonempty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        controls = kb.get_compliance_for_framework('CWE-287', 'nist_800_53')
        assert len(controls) >= 1

    def test_compliance_sensitive_data_hipaa(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        controls = kb.get_compliance_for_framework('CWE-312', 'hipaa')
        assert len(controls) >= 1

    def test_compliance_unknown_cwe_returns_none(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.get_compliance('CWE-9999') is None

    def test_compliance_for_framework_unknown_cwe_returns_empty(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        assert kb.get_compliance_for_framework('CWE-9999', 'pci_dss_v4') == []

    def test_all_frameworks_returns_tuple(self):
        from apps.scanning.engine.knowledge.remediation_kb import RemediationKB
        kb = RemediationKB()
        frameworks = kb.all_frameworks()
        assert isinstance(frameworks, tuple)
        assert len(frameworks) == 9

    def test_all_nine_framework_keys_present(self):
        from apps.scanning.engine.knowledge.remediation_kb import _ALL_FRAMEWORKS
        expected = {
            'owasp_top10_2021', 'owasp_api_top10_2023', 'owasp_llm_top10',
            'pci_dss_v4', 'soc2', 'iso_27001', 'nist_800_53', 'hipaa', 'gdpr',
        }
        assert set(_ALL_FRAMEWORKS) == expected

    def test_compliance_map_all_cwes_have_gdpr(self):
        from apps.scanning.engine.knowledge.remediation_kb import COMPLIANCE_MAP
        for cwe, mapping in COMPLIANCE_MAP.items():
            assert 'gdpr' in mapping, f'{cwe}: missing gdpr key in compliance map'

    def test_all_compliance_entries_have_owasp_top10(self):
        """All CWEs should have an OWASP Top 10 2021 mapping."""
        from apps.scanning.engine.knowledge.remediation_kb import COMPLIANCE_MAP
        for cwe, mapping in COMPLIANCE_MAP.items():
            assert 'owasp_top10_2021' in mapping, f'{cwe}: missing owasp_top10_2021'

    def test_compliance_ssrf_has_api_top10(self):
        from apps.scanning.engine.knowledge.remediation_kb import COMPLIANCE_MAP
        assert COMPLIANCE_MAP['CWE-918']['owasp_api_top10_2023'] is not None

    def test_compliance_sensitive_data_llm_top10(self):
        from apps.scanning.engine.knowledge.remediation_kb import COMPLIANCE_MAP
        # CWE-312 maps to LLM06
        assert COMPLIANCE_MAP['CWE-312']['owasp_llm_top10'] is not None


# ──────────────────────────────────────────────────────────────────────────────
# KnowledgeTester
# ──────────────────────────────────────────────────────────────────────────────

class TestKnowledgeTester:
    def test_tester_name(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        assert t.TESTER_NAME == 'Vulnerability Knowledge Base'

    def test_empty_url_returns_empty(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        assert t.test({'url': ''}) == []

    def test_no_findings_no_output(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        assert t.test({'url': 'https://example.com/'}, depth='deep') == []

    def test_finding_no_cwe_flagged(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'Mystery Bug', 'cwe': '', 'cvss': 5.0, 'severity': 'medium'}]}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('Missing CWE' in n for n in names)

    def test_finding_none_cwe_flagged(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'Bug', 'cwe': None, 'cvss': 3.0, 'severity': 'low'}]}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('Missing CWE' in n for n in names)

    def test_finding_with_cwe_no_uncategorized_flag(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'SQLi', 'cwe': 'CWE-89', 'cvss': 9.8, 'severity': 'critical'}]}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('Missing CWE' in n for n in names)

    def test_critical_zero_cvss_flagged(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'RCE', 'cwe': 'CWE-94', 'cvss': 0, 'severity': 'critical'}]}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('Missing CVSS' in n for n in names)

    def test_high_zero_cvss_flagged(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'SQLi', 'cwe': 'CWE-89', 'cvss': 0, 'severity': 'high'}]}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('Missing CVSS' in n for n in names)

    def test_low_zero_cvss_not_flagged(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'Info Leak', 'cwe': 'CWE-200', 'cvss': 0, 'severity': 'low'}]}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('Missing CVSS' in n for n in names)

    def test_critical_with_cvss_no_flag(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'RCE', 'cwe': 'CWE-94', 'cvss': 9.8, 'severity': 'critical'}]}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('Missing CVSS' in n for n in names)

    def test_compliance_check_runs_at_medium(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'SQLi', 'cwe': 'CWE-89', 'cvss': 9.8, 'severity': 'critical'}]}
        vulns = t.test(page, depth='medium', recon_data=recon)
        names = [v['name'] for v in vulns]
        # CWE-89 maps to PCI DSS, SOC2, etc.
        assert any('Compliance Risk' in n for n in names)

    def test_compliance_check_not_at_quick(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'SQLi', 'cwe': 'CWE-89', 'cvss': 9.8, 'severity': 'critical'}]}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('Compliance Risk' in n for n in names)

    def test_compliance_unknown_cwe_no_compliance_finding(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'Unknown', 'cwe': 'CWE-9999', 'cvss': 5.0, 'severity': 'medium'}]}
        vulns = t.test(page, depth='medium', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('Compliance Risk' in n for n in names)

    def test_remediation_check_at_deep_unknown_cwe(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'Custom Bug', 'cwe': 'CWE-9999', 'cvss': 5.0, 'severity': 'medium'}]}
        vulns = t.test(page, depth='deep', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('No Remediation Guidance' in n for n in names)

    def test_remediation_known_cwe_no_flag(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'SQLi', 'cwe': 'CWE-89', 'cvss': 9.8, 'severity': 'critical'}]}
        vulns = t.test(page, depth='deep', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('No Remediation Guidance' in n for n in names)

    def test_remediation_not_at_medium(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'Custom', 'cwe': 'CWE-9999', 'cvss': 5.0, 'severity': 'medium'}]}
        vulns = t.test(page, depth='medium', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('No Remediation Guidance' in n for n in names)

    def test_all_vulns_have_required_keys(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {
            'findings': [
                {'name': 'Bug A', 'cwe': '', 'cvss': 0, 'severity': 'critical'},
                {'name': 'Bug B', 'cwe': 'CWE-89', 'cvss': 9.8, 'severity': 'critical'},
                {'name': 'Bug C', 'cwe': 'CWE-9999', 'cvss': 5.0, 'severity': 'medium'},
            ]
        }
        vulns = t.test(page, depth='deep', recon_data=recon)
        for v in vulns:
            for key in ('name', 'severity', 'category', 'cwe', 'cvss',
                        'affected_url', 'evidence'):
                assert key in v, f'Missing key "{key}" in {v.get("name", "?")}'

    def test_clean_well_formed_findings_minimal_output(self):
        """All findings with correct CWE and CVSS should produce no quality flags."""
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {
            'findings': [
                {'name': 'SQLi', 'cwe': 'CWE-89', 'cvss': 9.8, 'severity': 'critical'},
                {'name': 'XSS', 'cwe': 'CWE-79', 'cvss': 6.1, 'severity': 'medium'},
            ]
        }
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('Missing CWE' in n for n in names)
        assert not any('Missing CVSS' in n for n in names)

    def test_empty_findings_list_no_output(self):
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': []}
        assert t.test(page, depth='deep', recon_data=recon) == []

    def test_multiple_uncategorized_one_finding(self):
        """Multiple no-CWE findings should produce a single combined flag."""
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {
            'findings': [
                {'name': 'Bug 1', 'cwe': '', 'cvss': 3.0, 'severity': 'low'},
                {'name': 'Bug 2', 'cwe': '', 'cvss': 3.0, 'severity': 'low'},
                {'name': 'Bug 3', 'cwe': '', 'cvss': 3.0, 'severity': 'low'},
            ]
        }
        vulns = t.test(page, depth='quick', recon_data=recon)
        uncategorized_findings = [v for v in vulns if 'Missing CWE' in v['name']]
        assert len(uncategorized_findings) == 1  # deduplicated into one flag

    def test_compliance_multiple_frameworks_for_one_cwe(self):
        """A single CWE should trigger compliance findings for all mapped frameworks."""
        from apps.scanning.engine.testers.knowledge_tester import KnowledgeTester
        from apps.scanning.engine.knowledge.remediation_kb import COMPLIANCE_MAP
        t = KnowledgeTester()
        page = {'url': 'https://example.com/'}
        recon = {'findings': [{'name': 'SQLi', 'cwe': 'CWE-89', 'cvss': 9.8, 'severity': 'critical'}]}
        vulns = t.test(page, depth='medium', recon_data=recon)
        compliance_findings = [v for v in vulns if 'Compliance Risk' in v['name']]
        # CWE-89 maps to several non-null frameworks
        mapping = COMPLIANCE_MAP['CWE-89']
        non_null = sum(1 for v in mapping.values() if v)
        assert len(compliance_findings) == non_null


# ──────────────────────────────────────────────────────────────────────────────
# Package imports
# ──────────────────────────────────────────────────────────────────────────────

class TestPackageImports:
    def test_all_exports_accessible(self):
        from apps.scanning.engine.knowledge import (
            VulnKB,
            RemediationKB,
            VULNERABILITY_DB,
            REMEDIATION_DB,
            COMPLIANCE_MAP,
        )
        assert callable(VulnKB)
        assert callable(RemediationKB)
        assert isinstance(VULNERABILITY_DB, dict)
        assert isinstance(REMEDIATION_DB, dict)
        assert isinstance(COMPLIANCE_MAP, dict)

    def test_vulnerability_db_len(self):
        from apps.scanning.engine.knowledge import VULNERABILITY_DB
        assert len(VULNERABILITY_DB) >= 10

    def test_remediation_db_len(self):
        from apps.scanning.engine.knowledge import REMEDIATION_DB
        assert len(REMEDIATION_DB) >= 10

    def test_compliance_map_len(self):
        from apps.scanning.engine.knowledge import COMPLIANCE_MAP
        assert len(COMPLIANCE_MAP) >= 10

    def test_dbs_have_same_cwe_keys(self):
        from apps.scanning.engine.knowledge import (
            VULNERABILITY_DB, REMEDIATION_DB, COMPLIANCE_MAP,
        )
        assert set(VULNERABILITY_DB.keys()) == set(REMEDIATION_DB.keys())
        assert set(VULNERABILITY_DB.keys()) == set(COMPLIANCE_MAP.keys())


# ──────────────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────────────

class TestRegistration:
    def test_tester_count_73(self):
        from apps.scanning.engine.testers import get_all_testers
        assert len(get_all_testers()) == 87

    def test_knowledge_tester_registered(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert 'Vulnerability Knowledge Base' in names

    def test_knowledge_tester_last(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert testers[-15].TESTER_NAME == 'Vulnerability Knowledge Base'
