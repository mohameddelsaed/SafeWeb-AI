"""
Phase 40 — Rate Limit & Stealth Mode Tests.

Tests for:
  - TrafficShaper        (engine/stealth/traffic_shaper.py)
  - FingerprintEvasion   (engine/stealth/fingerprint_evasion.py)
  - FingerprintProfile   dataclass
  - StealthTester        (testers/stealth_tester.py)
  - Package imports      (engine/stealth/__init__.py)
  - Registration (#72)
"""
import asyncio
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')
django.setup()


# ──────────────────────────────────────────────────────────────────────────────
# TrafficShaper — construction & validation
# ──────────────────────────────────────────────────────────────────────────────

class TestTrafficShaperInit:
    def test_default_construction(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper, DEFAULT_RPS
        s = TrafficShaper()
        assert s.rps == DEFAULT_RPS
        assert s.tor_enabled is False
        assert s.proxy_count == 0

    def test_custom_rps(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=5)
        assert s.rps == 5

    def test_rps_below_min_raises(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        with pytest.raises(ValueError, match='rps must be between'):
            TrafficShaper(rps=0)

    def test_rps_above_max_raises(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper, MAX_RPS
        with pytest.raises(ValueError):
            TrafficShaper(rps=MAX_RPS + 1)

    def test_invalid_jitter_raises(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        with pytest.raises(ValueError, match='jitter_pct'):
            TrafficShaper(jitter_pct=1.5)

    def test_negative_jitter_raises(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        with pytest.raises(ValueError):
            TrafficShaper(jitter_pct=-0.1)

    def test_proxies_stored(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(proxies=['http://proxy1:8080', 'http://proxy2:8080'])
        assert s.proxy_count == 2

    def test_tor_flag_stored(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(tor=True)
        assert s.tor_enabled is True


# ──────────────────────────────────────────────────────────────────────────────
# TrafficShaper — acquire / stats
# ──────────────────────────────────────────────────────────────────────────────

class TestTrafficShaperAcquire:
    def test_acquire_returns_float(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=100)
        result = s.acquire('example.com')
        assert isinstance(result, float)
        assert result >= 0.0

    def test_first_acquire_no_sleep(self):
        """First call per host should have zero sleep."""
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=1)
        result = s.acquire('newhost.test')
        assert result == 0.0

    def test_total_requests_tracked(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=100)
        for _ in range(3):
            s.acquire('tracker.test')
        st = s.stats('tracker.test')
        assert st['total_requests'] == 3

    def test_burst_tokens_decrease_on_rapid_calls(self):
        """Rapid sequential calls should consume burst tokens."""
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=1, jitter_pct=0.0)
        s.acquire('burst.test')               # first call — normal path
        initial = s.stats('burst.test')['burst_remaining']
        s.acquire('burst.test')               # immediate second — uses burst
        after = s.stats('burst.test')['burst_remaining']
        assert after < initial

    def test_stats_known_host(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=10)
        s.acquire('stats.test')
        st = s.stats('stats.test')
        assert st['known'] is True
        assert st['rps'] == 10
        assert isinstance(st['current_delay'], float)
        assert isinstance(st['base_delay'], float)
        assert isinstance(st['in_cooldown'], bool)

    def test_stats_unknown_host(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper()
        st = s.stats('never_seen.test')
        assert st['known'] is False

    def test_reset_host_clears_state(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=10)
        s.acquire('reset.test')
        s.reset_host('reset.test')
        assert s.stats('reset.test')['known'] is False

    def test_reset_all_clears_all_hosts(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=10)
        s.acquire('host1.test')
        s.acquire('host2.test')
        s.reset_all()
        assert s.stats('host1.test')['known'] is False
        assert s.stats('host2.test')['known'] is False


# ──────────────────────────────────────────────────────────────────────────────
# TrafficShaper — async acquire
# ──────────────────────────────────────────────────────────────────────────────

class TestTrafficShaperAsync:
    def test_async_acquire_returns_float(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=100)
        result = asyncio.run(s.async_acquire('async.test'))
        assert isinstance(result, float)
        assert result >= 0.0

    def test_async_first_call_no_sleep(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=1)
        result = asyncio.run(s.async_acquire('async_new.test'))
        assert result == 0.0

    def test_async_tracks_requests(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=100)

        async def run():
            await s.async_acquire('async_track.test')
            await s.async_acquire('async_track.test')

        asyncio.run(run())
        assert s.stats('async_track.test')['total_requests'] == 2


# ──────────────────────────────────────────────────────────────────────────────
# TrafficShaper — response feedback
# ──────────────────────────────────────────────────────────────────────────────

class TestTrafficShaperResponseFeedback:
    def test_429_increases_delay(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper, SLOWDOWN_FACTOR_429
        s = TrafficShaper(rps=10)
        s.acquire('resp.test')
        before = s.stats('resp.test')['current_delay']
        s.record_response('resp.test', 429)
        after = s.stats('resp.test')['current_delay']
        assert after > before
        assert abs(after / before - SLOWDOWN_FACTOR_429) < 0.001

    def test_503_increases_delay(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper, SLOWDOWN_FACTOR_503
        s = TrafficShaper(rps=10)
        s.acquire('resp503.test')
        before = s.stats('resp503.test')['current_delay']
        s.record_response('resp503.test', 503)
        after = s.stats('resp503.test')['current_delay']
        assert after > before
        assert abs(after / before - SLOWDOWN_FACTOR_503) < 0.001

    def test_200_eventually_recovers_delay(self):
        from apps.scanning.engine.stealth.traffic_shaper import (
            TrafficShaper, CLEAN_THRESHOLD,
        )
        s = TrafficShaper(rps=10)
        s.acquire('recovery.test')
        # First inflate the delay
        s.record_response('recovery.test', 429)
        inflated = s.stats('recovery.test')['current_delay']
        # Feed CLEAN_THRESHOLD clean responses to trigger recovery
        for _ in range(CLEAN_THRESHOLD):
            s.record_response('recovery.test', 200)
        recovered = s.stats('recovery.test')['current_delay']
        assert recovered < inflated

    def test_record_response_unknown_host_no_error(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper()
        s.record_response('ghost.test', 200)  # should not raise

    def test_delay_capped_at_60s(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(rps=10)
        s.acquire('cap.test')
        # Repeat 429s to try to exceed cap
        for _ in range(20):
            s.record_response('cap.test', 429)
        assert s.stats('cap.test')['current_delay'] <= 60.0


# ──────────────────────────────────────────────────────────────────────────────
# TrafficShaper — proxy / Tor
# ──────────────────────────────────────────────────────────────────────────────

class TestTrafficShaperProxy:
    def test_get_proxy_empty_returns_none(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper()
        assert s.get_proxy() is None

    def test_get_proxy_round_robin(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        proxies = ['http://p1:8080', 'http://p2:8080', 'http://p3:8080']
        s = TrafficShaper(proxies=proxies)
        results = [s.get_proxy() for _ in range(6)]
        assert results[0] == proxies[0]
        assert results[3] == proxies[0]  # cycle restarts

    def test_set_proxies_replaces_pool(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(proxies=['http://old:8080'])
        s.set_proxies(['http://new1:8080', 'http://new2:8080'])
        assert s.proxy_count == 2
        assert 'new1' in s.get_proxy()

    def test_enable_tor_returns_socks5_proxy(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper, TOR_SOCKS_DEFAULT_PORT
        s = TrafficShaper()
        s.enable_tor()
        proxy = s.get_proxy()
        assert proxy is not None
        assert 'socks5' in proxy
        assert str(TOR_SOCKS_DEFAULT_PORT) in proxy

    def test_enable_tor_custom_port(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper()
        s.enable_tor(socks_port=9151)
        assert '9151' in s.get_proxy()

    def test_disable_tor(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(tor=True)
        s.disable_tor()
        assert s.tor_enabled is False
        assert s.get_proxy() is None  # no proxies configured

    def test_tor_overrides_proxy_pool(self):
        """Tor should take priority over the proxy pool."""
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(proxies=['http://proxy:8080'], tor=True)
        proxy = s.get_proxy()
        assert 'socks5' in proxy

    def test_proxy_count_property(self):
        from apps.scanning.engine.stealth.traffic_shaper import TrafficShaper
        s = TrafficShaper(proxies=['http://a:1', 'http://b:2'])
        assert s.proxy_count == 2


# ──────────────────────────────────────────────────────────────────────────────
# FingerprintEvasion — User-Agent
# ──────────────────────────────────────────────────────────────────────────────

class TestFingerprintEvasionUserAgent:
    def test_get_user_agent_returns_string(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion()
        ua = e.get_user_agent()
        assert isinstance(ua, str)
        assert len(ua) > 20

    def test_ua_rotation_picks_from_pool(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion, UA_POOL
        e = FingerprintEvasion(ua_rotation=True)
        for _ in range(20):
            assert e.get_user_agent() in UA_POOL

    def test_ua_no_rotation_always_first(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion, UA_POOL
        e = FingerprintEvasion(ua_rotation=False)
        uas = {e.get_user_agent() for _ in range(10)}
        assert uas == {UA_POOL[0]}

    def test_custom_ua_pool(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        custom = ['CustomAgent/1.0', 'CustomAgent/2.0']
        e = FingerprintEvasion(ua_pool=custom)
        for _ in range(10):
            assert e.get_user_agent() in custom

    def test_ua_pool_global_all_unique(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import UA_POOL
        assert len(UA_POOL) == len(set(UA_POOL))

    def test_ua_pool_not_empty(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import UA_POOL
        assert len(UA_POOL) >= 10


# ──────────────────────────────────────────────────────────────────────────────
# FingerprintEvasion — TLS
# ──────────────────────────────────────────────────────────────────────────────

class TestFingerprintEvasionTLS:
    def test_tls_variation_returns_dict(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion(tls_variation=True)
        profile = e.get_tls_profile()
        assert isinstance(profile, dict)
        assert 'id' in profile
        assert 'cipher_suites' in profile

    def test_tls_no_variation_always_first_profile(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion, TLS_PROFILES
        e = FingerprintEvasion(tls_variation=False)
        for _ in range(10):
            assert e.get_tls_profile()['id'] == TLS_PROFILES[0]['id']

    def test_tls_variation_picks_from_pool(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion, TLS_PROFILES
        e = FingerprintEvasion(tls_variation=True)
        ids_seen = {e.get_tls_profile()['id'] for _ in range(50)}
        known_ids = {p['id'] for p in TLS_PROFILES}
        assert ids_seen.issubset(known_ids)

    def test_tls_profiles_all_have_id(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import TLS_PROFILES
        for p in TLS_PROFILES:
            assert 'id' in p
            assert 'cipher_suites' in p
            assert 'min_version' in p

    def test_tls_profiles_not_empty(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import TLS_PROFILES
        assert len(TLS_PROFILES) >= 3

    def test_get_tls_profile_returns_copy(self):
        """Mutations to returned dict should not affect internal pool."""
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion(tls_variation=False)
        profile = e.get_tls_profile()
        profile['injected'] = True
        fresh = e.get_tls_profile()
        assert 'injected' not in fresh


# ──────────────────────────────────────────────────────────────────────────────
# FingerprintEvasion — HTTP version
# ──────────────────────────────────────────────────────────────────────────────

class TestFingerprintEvasionHTTPVersion:
    def test_default_http_version_is_1_1(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion, HTTP_1_1
        e = FingerprintEvasion()
        assert e.get_http_version() == HTTP_1_1

    def test_http_version_variation_yields_both(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import (
            FingerprintEvasion, HTTP_1_1, HTTP_2,
        )
        e = FingerprintEvasion(http_version_variation=True)
        versions = {e.get_http_version() for _ in range(30)}
        assert HTTP_1_1 in versions
        assert HTTP_2 in versions

    def test_http_versions_constant(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import HTTP_VERSIONS, HTTP_1_1, HTTP_2
        assert HTTP_1_1 in HTTP_VERSIONS
        assert HTTP_2 in HTTP_VERSIONS


# ──────────────────────────────────────────────────────────────────────────────
# FingerprintEvasion — headers
# ──────────────────────────────────────────────────────────────────────────────

class TestFingerprintEvasionHeaders:
    def test_get_headers_required_keys(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion()
        h = e.get_headers()
        for key in ('User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding'):
            assert key in h

    def test_get_headers_base_merged(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion()
        h = e.get_headers(base_headers={'X-Custom': 'test', 'Content-Type': 'application/json'})
        assert h.get('X-Custom') == 'test'
        assert h.get('Content-Type') == 'application/json'

    def test_base_headers_do_not_override_ua(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion(ua_rotation=False)
        expected_ua = e.get_user_agent()
        h = e.get_headers(base_headers={'User-Agent': 'INJECTED'})
        assert h['User-Agent'] == expected_ua

    def test_randomize_header_order_same_keys(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion()
        original = {'A': '1', 'B': '2', 'C': '3', 'D': '4', 'E': '5'}
        shuffled = e.randomize_header_order(original)
        assert set(shuffled.keys()) == set(original.keys())
        assert set(shuffled.values()) == set(original.values())

    def test_header_randomization_produces_variation(self):
        """With randomization on, order should vary across enough samples."""
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion(header_randomization=True)
        orders = [tuple(e.get_headers().keys()) for _ in range(50)]
        unique_orders = set(orders)
        assert len(unique_orders) > 1


# ──────────────────────────────────────────────────────────────────────────────
# FingerprintProfile
# ──────────────────────────────────────────────────────────────────────────────

class TestFingerprintProfile:
    def test_profile_fields(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion()
        p = e.get_fingerprint_profile()
        assert isinstance(p.user_agent, str)
        assert isinstance(p.accept, str)
        assert isinstance(p.accept_language, str)
        assert isinstance(p.accept_encoding, str)
        assert isinstance(p.tls_profile, dict)
        assert isinstance(p.http_version, str)
        assert isinstance(p.headers, dict)

    def test_profile_ua_in_headers(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion()
        p = e.get_fingerprint_profile()
        assert p.headers.get('User-Agent') == p.user_agent

    def test_profile_with_base_headers(self):
        from apps.scanning.engine.stealth.fingerprint_evasion import FingerprintEvasion
        e = FingerprintEvasion()
        p = e.get_fingerprint_profile(base_headers={'Authorization': 'Bearer token123'})
        assert 'Authorization' in p.headers


# ──────────────────────────────────────────────────────────────────────────────
# StealthTester
# ──────────────────────────────────────────────────────────────────────────────

class TestStealthTester:
    def test_tester_name(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        assert t.TESTER_NAME == 'Stealth Mode Engine'

    def test_empty_url_returns_empty(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        assert t.test({'url': ''}) == []

    def test_high_rps_no_jitter_flagged(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='quick', recon_data={'stealth': {'rps': 100, 'jitter_pct': 0.0}})
        names = [v['name'] for v in vulns]
        assert any('No Rate Limiting' in n for n in names)

    def test_normal_rps_no_flag(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='quick', recon_data={'stealth': {'rps': 10}})
        names = [v['name'] for v in vulns]
        assert not any('No Rate Limiting' in n for n in names)

    def test_high_rps_with_jitter_no_flag(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='quick', recon_data={'stealth': {'rps': 100, 'jitter_pct': 0.30}})
        names = [v['name'] for v in vulns]
        assert not any('No Rate Limiting' in n for n in names)

    def test_ua_rotation_false_flagged(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='quick', recon_data={'stealth': {'ua_rotation': False}})
        names = [v['name'] for v in vulns]
        assert any('User-Agent Not Rotating' in n for n in names)

    def test_ua_rotation_true_no_flag(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        vulns = t.test(page, depth='quick', recon_data={'stealth': {'ua_rotation': True}})
        names = [v['name'] for v in vulns]
        assert not any('User-Agent' in n for n in names)

    def test_tls_variation_without_http_variation_medium(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        recon = {'stealth': {'tls_variation': True, 'http_version_variation': False}}
        vulns = t.test(page, depth='medium', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('TLS Variation' in n for n in names)

    def test_tls_variation_check_not_run_at_quick(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        recon = {'stealth': {'tls_variation': True, 'http_version_variation': False}}
        vulns = t.test(page, depth='quick', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('TLS Variation' in n for n in names)

    def test_tls_and_http_variation_no_flag(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        recon = {'stealth': {'tls_variation': True, 'http_version_variation': True}}
        vulns = t.test(page, depth='medium', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('TLS Variation' in n for n in names)

    def test_high_risk_no_proxy_flagged_at_deep(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://target.example.com/'}
        recon = {'scan_risk': 'high', 'stealth': {}}
        vulns = t.test(page, depth='deep', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert any('No Proxy' in n for n in names)

    def test_high_risk_with_proxy_no_flag(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://target.example.com/'}
        recon = {'scan_risk': 'high', 'stealth': {'proxy': 'socks5://127.0.0.1:9050'}}
        vulns = t.test(page, depth='deep', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('No Proxy' in n for n in names)

    def test_high_risk_with_tor_no_flag(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://target.example.com/'}
        recon = {'scan_risk': 'high', 'stealth': {'tor_enabled': True}}
        vulns = t.test(page, depth='deep', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('No Proxy' in n for n in names)

    def test_normal_risk_no_proxy_not_flagged(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        recon = {'scan_risk': 'normal', 'stealth': {}}
        vulns = t.test(page, depth='deep', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('No Proxy' in n for n in names)

    def test_proxy_check_not_run_at_medium(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://target.example.com/'}
        recon = {'scan_risk': 'high', 'stealth': {}}
        vulns = t.test(page, depth='medium', recon_data=recon)
        names = [v['name'] for v in vulns]
        assert not any('No Proxy' in n for n in names)

    def test_all_vulns_are_dicts_with_required_keys(self):
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        recon = {
            'scan_risk': 'high',
            'stealth': {
                'rps': 100,
                'jitter_pct': 0.0,
                'ua_rotation': False,
                'tls_variation': True,
                'http_version_variation': False,
            },
        }
        vulns = t.test(page, depth='deep', recon_data=recon)
        for v in vulns:
            assert isinstance(v, dict)
            for key in ('name', 'severity', 'category', 'cwe', 'cvss',
                        'affected_url', 'evidence'):
                assert key in v, f'Missing key {key} in {v["name"]}'

    def test_clean_config_no_findings(self):
        """A properly configured stealth setup should produce no findings."""
        from apps.scanning.engine.testers.stealth_tester import StealthTester
        t = StealthTester()
        page = {'url': 'https://example.com/'}
        recon = {
            'scan_risk': 'normal',
            'stealth': {
                'rps': 5,
                'jitter_pct': 0.30,
                'ua_rotation': True,
                'tls_variation': True,
                'http_version_variation': True,
            },
        }
        vulns = t.test(page, depth='deep', recon_data=recon)
        assert vulns == []


# ──────────────────────────────────────────────────────────────────────────────
# Package imports
# ──────────────────────────────────────────────────────────────────────────────

class TestPackageImports:
    def test_all_exports_accessible(self):
        from apps.scanning.engine.stealth import (
            TrafficShaper,
            FingerprintEvasion,
        )
        assert callable(TrafficShaper)
        assert callable(FingerprintEvasion)

    def test_constants_sensible(self):
        from apps.scanning.engine.stealth import (
            DEFAULT_RPS, MIN_RPS, MAX_RPS,
            DEFAULT_JITTER_PCT, TOR_SOCKS_DEFAULT_PORT,
        )
        assert MIN_RPS >= 1
        assert MAX_RPS <= 100
        assert MIN_RPS < DEFAULT_RPS < MAX_RPS
        assert 0.0 < DEFAULT_JITTER_PCT < 1.0
        assert TOR_SOCKS_DEFAULT_PORT == 9050


# ──────────────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────────────

class TestRegistration:
    def test_tester_count_73(self):
        from apps.scanning.engine.testers import get_all_testers
        assert len(get_all_testers()) == 87

    def test_stealth_tester_registered(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert 'Stealth Mode Engine' in names

    def test_stealth_tester_position(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert testers[-16].TESTER_NAME == 'Stealth Mode Engine'
