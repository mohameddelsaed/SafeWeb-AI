"""
Phase 39 — Scan Profile & Template System Tests.

Tests for:
  - ScanProfile dataclass          (engine/profiles/scan_profiles.py)
  - Built-in profiles (9 profiles)
  - ProfileRegistry
  - ProfileBuilder
  - Profile validation
  - create_custom_profile()
  - recommend_profile()
  - ScanProfileTester               (testers/scan_profile_tester.py)
  - Registration (#71)
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')
django.setup()

# ──────────────────────────────────────────────────────────────────────────────
# ScanProfile dataclass
# ──────────────────────────────────────────────────────────────────────────────

class TestScanProfileDataclass:
    def test_to_dict_keys(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='test', name='Test', description='desc', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=30, testers=['*'],
            nuclei_tags=['high'], stealth_level=STEALTH_NORMAL,
            rps=10, scope_aware=False,
        )
        d = p.to_dict()
        for key in ('id', 'name', 'description', 'is_builtin', 'depth',
                    'max_duration_minutes', 'testers', 'nuclei_tags',
                    'stealth_level', 'rps', 'scope_aware', 'config'):
            assert key in d

    def test_from_dict_round_trip(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_DEEP, STEALTH_STEALTH
        original = ScanProfile(
            id='rt_test', name='Round Trip', description='test',
            is_builtin=False, depth=DEPTH_DEEP, max_duration_minutes=-1,
            testers=['SQL Injection Tester', 'XSS Tester'],
            nuclei_tags=['critical'], stealth_level=STEALTH_STEALTH,
            rps=2, scope_aware=True, config={'foo': 'bar'},
        )
        restored = ScanProfile.from_dict(original.to_dict())
        assert restored.id == original.id
        assert restored.depth == original.depth
        assert restored.testers == original.testers
        assert restored.config == original.config

    def test_includes_all_testers_star(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=10, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        assert p.includes_all_testers() is True

    def test_includes_all_testers_explicit_list(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=10,
            testers=['SQL Injection Tester'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        assert p.includes_all_testers() is False

    def test_has_tester_with_star(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=10, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        assert p.has_tester('Anything') is True

    def test_has_tester_explicit(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=10,
            testers=['SQL Injection Tester', 'XSS Tester'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        assert p.has_tester('SQL Injection Tester') is True
        assert p.has_tester('SSRF Tester') is False

    def test_is_unlimited(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_DEEP, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=True,
            depth=DEPTH_DEEP, max_duration_minutes=-1, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=5, scope_aware=False,
        )
        assert p.is_unlimited() is True

    def test_uses_all_nuclei(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_DEEP, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=True,
            depth=DEPTH_DEEP, max_duration_minutes=-1, testers=['*'],
            nuclei_tags=['*'], stealth_level=STEALTH_NORMAL, rps=5, scope_aware=False,
        )
        assert p.uses_all_nuclei() is True

    def test_is_valid_for_correct_profile(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='valid_id', name='Valid', description='ok', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=30, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        assert p.is_valid() is True
        assert p.validate() == []


# ──────────────────────────────────────────────────────────────────────────────
# Profile Validation
# ──────────────────────────────────────────────────────────────────────────────

class TestProfileValidation:
    def test_invalid_depth_raises_error(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=False,
            depth='superdeep', max_duration_minutes=30, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        errors = p.validate()
        assert any('depth' in e for e in errors)

    def test_empty_id_raises_error(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='', name='X', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=30, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        assert any('id' in e for e in p.validate())

    def test_empty_name_raises_error(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='valid', name='', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=30, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        assert any('name' in e for e in p.validate())

    def test_zero_rps_raises_error(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=30, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=0, scope_aware=False,
        )
        assert any('rps' in e for e in p.validate())

    def test_empty_testers_raises_error(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=30, testers=[],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        assert any('tester' in e for e in p.validate())

    def test_invalid_stealth_level(self):
        from apps.scanning.engine.profiles.scan_profiles import ScanProfile, DEPTH_MEDIUM
        p = ScanProfile(
            id='x', name='X', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=30, testers=['*'],
            nuclei_tags=[], stealth_level='ninja', rps=10, scope_aware=False,
        )
        assert any('stealth_level' in e for e in p.validate())


# ──────────────────────────────────────────────────────────────────────────────
# Built-in Profiles
# ──────────────────────────────────────────────────────────────────────────────

class TestBuiltinProfiles:
    def test_nine_builtin_profiles_defined(self):
        from apps.scanning.engine.profiles.scan_profiles import BUILTIN_PROFILES
        assert len(BUILTIN_PROFILES) == 9

    def test_all_builtin_profiles_are_valid(self):
        from apps.scanning.engine.profiles.scan_profiles import BUILTIN_PROFILES
        for p in BUILTIN_PROFILES:
            errors = p.validate()
            assert errors == [], f'Profile {p.id!r} has errors: {errors}'

    def test_all_builtin_ids_unique(self):
        from apps.scanning.engine.profiles.scan_profiles import BUILTIN_PROFILES
        ids = [p.id for p in BUILTIN_PROFILES]
        assert len(ids) == len(set(ids))

    def test_quick_scan_profile(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, QUICK_SCAN
        p = REGISTRY.get(QUICK_SCAN)
        assert p is not None
        assert p.depth == 'quick'
        assert p.max_duration_minutes == 5
        assert p.rps == 20

    def test_standard_scan_all_testers(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, STANDARD_SCAN
        p = REGISTRY.get(STANDARD_SCAN)
        assert p.includes_all_testers()
        assert p.depth == 'medium'

    def test_deep_scan_unlimited(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, DEEP_SCAN
        p = REGISTRY.get(DEEP_SCAN)
        assert p.is_unlimited()
        assert p.uses_all_nuclei()

    def test_api_scan_api_mode(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, API_SCAN
        p = REGISTRY.get(API_SCAN)
        assert p.config.get('api_mode') is True

    def test_compliance_scan_generates_report(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, COMPLIANCE_SCAN
        p = REGISTRY.get(COMPLIANCE_SCAN)
        assert p.config.get('generate_report') is True

    def test_bug_bounty_scope_aware(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, BUG_BOUNTY_SCAN
        p = REGISTRY.get(BUG_BOUNTY_SCAN)
        assert p.scope_aware is True
        assert p.stealth_level == 'stealth'
        assert p.rps == 2

    def test_red_team_active_exploitation(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, RED_TEAM_SCAN
        p = REGISTRY.get(RED_TEAM_SCAN)
        assert p.config.get('active_exploitation') is True
        assert p.depth == 'deep'

    def test_wordpress_scan_cms_config(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, WORDPRESS_SCAN
        p = REGISTRY.get(WORDPRESS_SCAN)
        assert p.config.get('cms') == 'wordpress'
        assert p.config.get('enumerate_users') is True

    def test_auth_scan_authenticated(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, AUTH_SCAN
        p = REGISTRY.get(AUTH_SCAN)
        assert p.config.get('authenticated') is True

    def test_all_builtins_have_descriptions(self):
        from apps.scanning.engine.profiles.scan_profiles import BUILTIN_PROFILES
        for p in BUILTIN_PROFILES:
            assert len(p.description) > 10, f'{p.id} has no description'

    def test_all_builtins_have_nuclei_tags(self):
        from apps.scanning.engine.profiles.scan_profiles import BUILTIN_PROFILES
        for p in BUILTIN_PROFILES:
            assert len(p.nuclei_tags) > 0, f'{p.id} has no nuclei tags'


# ──────────────────────────────────────────────────────────────────────────────
# ProfileRegistry
# ──────────────────────────────────────────────────────────────────────────────

class TestProfileRegistry:
    def test_registry_contains_nine_builtins(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY
        assert len(REGISTRY.list_builtin()) == 9

    def test_get_returns_correct_profile(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, QUICK_SCAN
        p = REGISTRY.get(QUICK_SCAN)
        assert p is not None
        assert p.id == QUICK_SCAN

    def test_get_unknown_returns_none(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY
        assert REGISTRY.get('non_existent_profile_xyz') is None

    def test_register_custom_profile(self):
        from apps.scanning.engine.profiles.scan_profiles import (
            ProfileRegistry, ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL,
        )
        reg = ProfileRegistry()
        p = ScanProfile(
            id='my_test', name='My Test', description='test', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=15, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=5, scope_aware=False,
        )
        reg.register(p)
        assert 'my_test' in reg
        assert reg.get('my_test') is p

    def test_deregister_removes_profile(self):
        from apps.scanning.engine.profiles.scan_profiles import (
            ProfileRegistry, ScanProfile, DEPTH_QUICK, STEALTH_AGGRESSIVE,
        )
        reg = ProfileRegistry()
        p = ScanProfile(
            id='to_remove', name='Remove', description='', is_builtin=False,
            depth=DEPTH_QUICK, max_duration_minutes=5, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_AGGRESSIVE, rps=10, scope_aware=False,
        )
        reg.register(p)
        removed = reg.deregister('to_remove')
        assert removed is True
        assert reg.get('to_remove') is None

    def test_deregister_nonexistent_returns_false(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileRegistry
        reg = ProfileRegistry()
        assert reg.deregister('ghost') is False

    def test_list_custom_profiles(self):
        from apps.scanning.engine.profiles.scan_profiles import (
            ProfileRegistry, ScanProfile, DEPTH_MEDIUM, STEALTH_NORMAL, BUILTIN_PROFILES,
        )
        reg = ProfileRegistry()
        for bp in BUILTIN_PROFILES:
            reg.register(bp)
        custom = ScanProfile(
            id='custom_one', name='Custom One', description='', is_builtin=False,
            depth=DEPTH_MEDIUM, max_duration_minutes=20, testers=['*'],
            nuclei_tags=[], stealth_level=STEALTH_NORMAL, rps=10, scope_aware=False,
        )
        reg.register(custom)
        assert len(reg.list_custom()) == 1
        assert reg.list_custom()[0].id == 'custom_one'

    def test_len(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileRegistry, BUILTIN_PROFILES
        reg = ProfileRegistry()
        for bp in BUILTIN_PROFILES:
            reg.register(bp)
        assert len(reg) == 9

    def test_contains_operator(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY, STANDARD_SCAN
        assert STANDARD_SCAN in REGISTRY
        assert 'not_a_profile_xyz' not in REGISTRY

    def test_iter_yields_profiles(self):
        from apps.scanning.engine.profiles.scan_profiles import REGISTRY
        ids = [p.id for p in REGISTRY]
        assert len(ids) == len(set(ids))
        assert 'quick_scan' in ids


# ──────────────────────────────────────────────────────────────────────────────
# ProfileBuilder
# ──────────────────────────────────────────────────────────────────────────────

class TestProfileBuilder:
    def test_build_with_defaults(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileBuilder
        p = ProfileBuilder().build()
        assert p.id == 'custom_profile'
        assert p.depth == 'medium'
        assert p.rps == 10
        assert p.is_builtin is False
        assert p.testers == ['*']  # defaults to all when none specified

    def test_fluent_setters(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileBuilder
        p = (
            ProfileBuilder()
            .set_id('my_scan')
            .set_name('My Scan')
            .set_description('A test profile')
            .set_depth('deep')
            .set_rps(3)
            .set_max_duration(-1)
            .enable_scope_awareness(True)
            .build()
        )
        assert p.id == 'my_scan'
        assert p.name == 'My Scan'
        assert p.description == 'A test profile'
        assert p.depth == 'deep'
        assert p.rps == 3
        assert p.is_unlimited()
        assert p.scope_aware is True

    def test_enable_tester_idempotent(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileBuilder
        b = ProfileBuilder()
        b.enable_tester('SQL Injection Tester')
        b.enable_tester('SQL Injection Tester')  # duplicate
        b.enable_tester('XSS Tester')
        p = b.build()
        assert p.testers.count('SQL Injection Tester') == 1
        assert 'XSS Tester' in p.testers

    def test_disable_tester(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileBuilder
        p = (
            ProfileBuilder()
            .set_testers(['SQL Injection Tester', 'XSS Tester', 'Auth Tester'])
            .disable_tester('XSS Tester')
            .build()
        )
        assert 'XSS Tester' not in p.testers
        assert 'SQL Injection Tester' in p.testers

    def test_set_nuclei_tags(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileBuilder
        p = ProfileBuilder().set_nuclei_tags(['critical', 'high']).build()
        assert p.nuclei_tags == ['critical', 'high']

    def test_set_config_kwargs(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileBuilder
        p = ProfileBuilder().set_config(api_mode=True, max_pages=100).build()
        assert p.config.get('api_mode') is True
        assert p.config.get('max_pages') == 100

    def test_from_profile_fork(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileBuilder, REGISTRY, QUICK_SCAN
        quick = REGISTRY.get(QUICK_SCAN)
        forked = ProfileBuilder().from_profile(quick).set_rps(1).build()
        assert forked.id == QUICK_SCAN + '_fork'
        assert forked.is_builtin is False
        assert forked.rps == 1
        # Original should be unchanged
        assert REGISTRY.get(QUICK_SCAN).rps == 20

    def test_build_does_not_register(self):
        from apps.scanning.engine.profiles.scan_profiles import ProfileBuilder, REGISTRY
        unique_id = 'test_not_registered_9999'
        ProfileBuilder().set_id(unique_id).build()
        assert REGISTRY.get(unique_id) is None


# ──────────────────────────────────────────────────────────────────────────────
# create_custom_profile()
# ──────────────────────────────────────────────────────────────────────────────

class TestCreateCustomProfile:
    def test_creates_profile_with_name(self):
        from apps.scanning.engine.profiles.scan_profiles import create_custom_profile
        p = create_custom_profile('My Custom Scan')
        assert p.name == 'My Custom Scan'
        assert p.is_builtin is False

    def test_slug_generated_from_name(self):
        from apps.scanning.engine.profiles.scan_profiles import create_custom_profile
        p = create_custom_profile('My Custom Scan 2026')
        assert ' ' not in p.id

    def test_register_true_adds_to_registry(self):
        from apps.scanning.engine.profiles.scan_profiles import create_custom_profile, REGISTRY
        p = create_custom_profile('Reg Test Profile', register=True)
        assert REGISTRY.get(p.id) is p
        REGISTRY.deregister(p.id)  # cleanup

    def test_custom_depth_and_rps(self):
        from apps.scanning.engine.profiles.scan_profiles import create_custom_profile
        p = create_custom_profile('Quick Custom', depth='quick', rps=25)
        assert p.depth == 'quick'
        assert p.rps == 25

    def test_explicit_testers_list(self):
        from apps.scanning.engine.profiles.scan_profiles import create_custom_profile
        p = create_custom_profile(
            'Limited Scan',
            testers=['SQL Injection Tester', 'Auth Tester'],
        )
        assert 'SQL Injection Tester' in p.testers
        assert 'Auth Tester' in p.testers
        assert p.includes_all_testers() is False


# ──────────────────────────────────────────────────────────────────────────────
# recommend_profile()
# ──────────────────────────────────────────────────────────────────────────────

class TestRecommendProfile:
    def test_default_recommends_standard_scan(self):
        from apps.scanning.engine.profiles.scan_profiles import recommend_profile, STANDARD_SCAN
        p = recommend_profile({})
        assert p.id == STANDARD_SCAN

    def test_wordpress_recommends_wordpress_scan(self):
        from apps.scanning.engine.profiles.scan_profiles import recommend_profile, WORDPRESS_SCAN
        recon = {
            'technologies': {
                'technologies': [{'name': 'WordPress', 'category': 'CMS'}],
            }
        }
        p = recommend_profile(recon)
        assert p.id == WORDPRESS_SCAN

    def test_api_only_recommends_api_scan(self):
        from apps.scanning.engine.profiles.scan_profiles import recommend_profile, API_SCAN
        p = recommend_profile({'api_only': True})
        assert p.id == API_SCAN

    def test_has_auth_recommends_auth_scan(self):
        from apps.scanning.engine.profiles.scan_profiles import recommend_profile, AUTH_SCAN
        p = recommend_profile({'has_auth': True})
        assert p.id == AUTH_SCAN

    def test_wordpress_takes_priority_over_api(self):
        from apps.scanning.engine.profiles.scan_profiles import recommend_profile, WORDPRESS_SCAN
        # WordPress detection should override api_only flag
        recon = {
            'api_only': True,
            'technologies': {
                'technologies': [{'name': 'WordPress', 'category': 'CMS'}],
            }
        }
        p = recommend_profile(recon)
        assert p.id == WORDPRESS_SCAN

    def test_returns_valid_profile(self):
        from apps.scanning.engine.profiles.scan_profiles import recommend_profile
        p = recommend_profile({'unknown_key': True})
        assert p is not None
        assert p.is_valid()


# ──────────────────────────────────────────────────────────────────────────────
# Convenience functions
# ──────────────────────────────────────────────────────────────────────────────

class TestConvenienceFunctions:
    def test_get_profile_returns_profile(self):
        from apps.scanning.engine.profiles.scan_profiles import get_profile, DEEP_SCAN
        p = get_profile(DEEP_SCAN)
        assert p is not None
        assert p.id == DEEP_SCAN

    def test_get_profile_unknown_returns_none(self):
        from apps.scanning.engine.profiles.scan_profiles import get_profile
        assert get_profile('does_not_exist') is None

    def test_list_profiles_includes_all_builtins(self):
        from apps.scanning.engine.profiles.scan_profiles import list_profiles, _BUILTIN_IDS
        all_ids = [p.id for p in list_profiles()]
        for bid in _BUILTIN_IDS:
            assert bid in all_ids

    def test_list_builtin_profiles_length(self):
        from apps.scanning.engine.profiles.scan_profiles import list_builtin_profiles
        assert len(list_builtin_profiles()) == 9


# ──────────────────────────────────────────────────────────────────────────────
# ScanProfileTester
# ──────────────────────────────────────────────────────────────────────────────

class TestScanProfileTester:
    def test_instantiation(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        assert t.TESTER_NAME == 'Scan Profile Engine'

    def test_empty_url_returns_empty(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        assert t.test({'url': ''}) == []

    def test_no_profile_generates_recommendation(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='quick', recon_data={})
        names = [v['name'] for v in vulns]
        assert any('No Profile Selected' in n for n in names)

    def test_recommendation_finding_is_info(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='quick', recon_data={})
        for v in vulns:
            if 'No Profile Selected' in v['name']:
                assert v['severity'] == 'info'
                assert v['cvss'] == 0.0
                break

    def test_standard_scan_no_coverage_gaps(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        # Standard scan uses all testers — no coverage gaps expected
        recon = {'scan_profile': 'standard_scan'}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        # With a valid profile selected, no recommendation finding
        assert not any('No Profile Selected' in n for n in names)
        # No coverage gap (standard uses all testers)
        assert not any('Missing Essential Testers' in n for n in names)

    def test_limited_profile_generates_coverage_finding(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        from apps.scanning.engine.profiles.scan_profiles import (
            create_custom_profile, REGISTRY,
        )
        # Create a custom profile missing essential testers
        p = create_custom_profile(
            'Tiny Scan Coverage Test',
            testers=['Component Vulnerability Tester'],
            register=True,
        )
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='quick', recon_data={'scan_profile': p.id})
        names = [v['name'] for v in vulns]
        assert any('Missing Essential Testers' in n for n in names)
        REGISTRY.deregister(p.id)  # cleanup

    def test_wordpress_detected_with_wrong_profile(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        page = {'url': 'https://blog.example.com/'}
        recon = {
            'scan_profile': 'standard_scan',
            'technologies': {
                'technologies': [{'name': 'WordPress', 'category': 'CMS'}],
            },
        }
        vulns = t.test(page, depth='medium', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('WordPress' in n for n in names)

    def test_depth_mismatch_for_wordpress(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        page = {'url': 'https://wp.example.com/'}
        # quick_scan on a WordPress target — recommend wordpress_scan (deep)
        recon = {
            'scan_profile': 'quick_scan',
            'technologies': {
                'technologies': [{'name': 'WordPress', 'category': 'CMS'}],
            },
        }
        vulns = t.test(page, depth='medium', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('Insufficient Depth' in n or 'WordPress' in n for n in names)

    def test_deep_depth_stealth_assessment(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        recon = {'scan_profile': 'bug_bounty_scan'}
        vulns = t.test(page, depth='deep', recon_data=recon)
        # bug_bounty_scan is scope_aware=True by default, should be fine
        names = [v['name'] for v in vulns]
        # Should NOT produce the scope-enforcement warning (it's already configured correctly)
        assert not any('Scope Not Enforced' in n for n in names)

    def test_all_vulns_are_dicts_with_required_keys(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='deep', recon_data={})
        for v in vulns:
            assert isinstance(v, dict)
            for key in ('name', 'severity', 'category', 'cwe', 'cvss',
                        'affected_url', 'evidence'):
                assert key in v, f'Missing key {key} in {v["name"]}'

    def test_quick_depth_no_config_gap_check(self):
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        recon = {
            'scan_profile': 'quick_scan',
            'technologies': {
                'technologies': [{'name': 'WordPress'}],
            },
        }
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        # Config gap checks (WordPress mismatch) only run at medium+
        assert not any('Insufficient Depth' in n for n in names)
        assert not any('WordPress Target Without WordPress Profile' in n for n in names)


# ──────────────────────────────────────────────────────────────────────────────
# Stealth configuration assessment
# ──────────────────────────────────────────────────────────────────────────────

class TestStealthConfigAssessment:
    def test_high_rps_stealth_profile_flagged(self):
        """A custom stealth profile with rps>10 should trigger a finding."""
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        from apps.scanning.engine.profiles.scan_profiles import (
            create_custom_profile, REGISTRY,
        )
        bad_stealth = create_custom_profile(
            'Bad Stealth Config Test',
            stealth_level='stealth',
            rps=50,
            register=True,
        )
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='deep', recon_data={'scan_profile': bad_stealth.id})
        names = [v['name'] for v in vulns]
        assert any('High RPS Undermines Stealth' in n for n in names)
        REGISTRY.deregister(bad_stealth.id)

    def test_normal_stealth_high_rps_not_flagged(self):
        """Normal stealth level with high RPS is acceptable."""
        from apps.scanning.engine.testers.scan_profile_tester import ScanProfileTester
        from apps.scanning.engine.profiles.scan_profiles import (
            create_custom_profile, REGISTRY,
        )
        normal = create_custom_profile(
            'Normal High RPS Test',
            stealth_level='normal',
            rps=50,
            register=True,
        )
        t = ScanProfileTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='deep', recon_data={'scan_profile': normal.id})
        names = [v['name'] for v in vulns]
        assert not any('High RPS Undermines Stealth' in n for n in names)
        REGISTRY.deregister(normal.id)


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

class TestProfileConstants:
    def test_depth_constants_defined(self):
        from apps.scanning.engine.profiles.scan_profiles import (
            DEPTH_QUICK, DEPTH_MEDIUM, DEPTH_DEEP,
        )
        assert DEPTH_QUICK == 'quick'
        assert DEPTH_MEDIUM == 'medium'
        assert DEPTH_DEEP == 'deep'

    def test_stealth_constants_defined(self):
        from apps.scanning.engine.profiles.scan_profiles import (
            STEALTH_AGGRESSIVE, STEALTH_NORMAL, STEALTH_STEALTH,
        )
        assert STEALTH_AGGRESSIVE == 'aggressive'
        assert STEALTH_NORMAL == 'normal'
        assert STEALTH_STEALTH == 'stealth'

    def test_builtin_id_constants(self):
        from apps.scanning.engine.profiles.scan_profiles import (
            QUICK_SCAN, STANDARD_SCAN, DEEP_SCAN, API_SCAN, COMPLIANCE_SCAN,
            BUG_BOUNTY_SCAN, RED_TEAM_SCAN, WORDPRESS_SCAN, AUTH_SCAN,
        )
        ids = [
            QUICK_SCAN, STANDARD_SCAN, DEEP_SCAN, API_SCAN, COMPLIANCE_SCAN,
            BUG_BOUNTY_SCAN, RED_TEAM_SCAN, WORDPRESS_SCAN, AUTH_SCAN,
        ]
        assert len(ids) == len(set(ids))  # all unique

    def test_package_imports(self):
        """All names exported from engine/profiles/__init__.py are accessible."""
        from apps.scanning.engine.profiles import (
            REGISTRY,
            get_profile, recommend_profile,
        )
        assert REGISTRY is not None
        assert callable(get_profile)
        assert callable(recommend_profile)


# ──────────────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────────────

class TestRegistration:
    def test_tester_count_71(self):
        from apps.scanning.engine.testers import get_all_testers
        assert len(get_all_testers()) == 87

    def test_scan_profile_tester_registered(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert 'Scan Profile Engine' in names

    def test_scan_profile_tester_position(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert testers[-17].TESTER_NAME == 'Scan Profile Engine'
