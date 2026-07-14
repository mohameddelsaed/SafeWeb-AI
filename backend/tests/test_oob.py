"""Tests for Phase 19 — OOB Callback Infrastructure."""
import time
from unittest.mock import patch, MagicMock
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@dataclass
class MockPage:
    url: str
    status_code: int = 200
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    body: str = ''
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    js_rendered: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# InteractshClient Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestInteractshClient:
    """Test suite for InteractshClient."""

    def setup_method(self):
        from apps.scanning.engine.oob.interactsh_client import InteractshClient
        self.client = InteractshClient(server='test.oast.live')

    def test_register_success(self):
        """Test successful registration with Interactsh server."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}

        with patch.object(self.client._session, 'post', return_value=mock_resp):
            url = self.client.register()

        assert url is not None
        assert 'test.oast.live' in url
        assert self.client.is_registered is True
        assert self.client.interaction_url is not None

    def test_register_failure_graceful(self):
        """Test graceful handling when registration fails."""
        import requests
        with patch.object(
            self.client._session, 'post',
            side_effect=requests.RequestException('Connection refused'),
        ):
            url = self.client.register()

        # Should still return a fallback URL
        assert url is not None
        assert 'test.oast.live' in url
        assert self.client.is_registered is False

    def test_poll_returns_interactions(self):
        """Test polling returns parsed interactions."""
        self.client._correlation_id = 'test-correlation'
        self.client._secret_key = 'test-secret'
        self.client._registered = True

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'data': [
                {
                    'protocol': 'dns',
                    'full-id': 'sqli-id-abc123.test-correlation.test.oast.live',
                    'raw-request': 'DNS query for sqli-id-abc123...',
                    'remote-address': '1.2.3.4',
                    'timestamp': '2025-01-01T00:00:00Z',
                    'q-type': 'A',
                },
            ],
        }

        with patch.object(self.client._session, 'get', return_value=mock_resp):
            interactions = self.client.poll()

        assert len(interactions) == 1
        assert interactions[0].protocol == 'dns'
        assert interactions[0].remote_address == '1.2.3.4'

    def test_poll_empty_when_not_registered(self):
        """Test poll returns empty list when not registered."""
        interactions = self.client.poll()
        assert interactions == []

    def test_poll_handles_network_error(self):
        """Test poll handles network errors gracefully."""
        self.client._correlation_id = 'test'
        self.client._secret_key = 'test'
        import requests
        with patch.object(
            self.client._session, 'get',
            side_effect=requests.RequestException('timeout'),
        ):
            interactions = self.client.poll()
        assert interactions == []

    def test_generate_subdomain(self):
        """Test unique subdomain generation for payloads."""
        self.client._correlation_id = 'test-corr'
        self.client._registered = True
        self.client.interaction_url = 'test-corr.test.oast.live'

        sub1 = self.client.generate_subdomain('sqli-param-id')
        sub2 = self.client.generate_subdomain('sqli-param-id')

        assert 'test-corr.test.oast.live' in sub1
        assert 'sqli-param-id' in sub1
        # Each call generates a unique subdomain
        assert sub1 != sub2

    def test_close_deregisters(self):
        """Test close sends deregister request."""
        self.client._correlation_id = 'test-corr'
        self.client._secret_key = 'test-secret'
        self.client._registered = True

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch.object(self.client._session, 'post', return_value=mock_resp) as mock_post:
            self.client.close()

        assert self.client._registered is False
        mock_post.assert_called_once()

    def test_context_manager(self):
        """Test the context manager protocol."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch.object(self.client._session, 'post', return_value=mock_resp):
            with self.client as client:
                assert client.interaction_url is not None

        assert self.client._registered is False


# ═══════════════════════════════════════════════════════════════════════════
# OOBManager Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestOOBManager:
    """Test suite for OOBManager."""

    def setup_method(self):
        from apps.scanning.engine.oob.oob_manager import OOBManager
        self.manager = OOBManager(server='test.oast.live')

    def test_start_success(self):
        """Test OOB manager starts successfully."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch('apps.scanning.engine.oob.interactsh_client.InteractshClient.register',
                    return_value='test-id.test.oast.live'):
            result = self.manager.start()
        assert result is True
        assert self.manager.is_active is True

    def test_start_failure(self):
        """Test OOB manager handles start failure."""
        with patch('apps.scanning.engine.oob.interactsh_client.InteractshClient.register',
                    side_effect=Exception('Connection failed')):
            result = self.manager.start()
        assert result is False
        assert self.manager.is_active is False

    def test_generate_oob_payloads_sqli(self):
        """Test OOB payload generation for blind SQLi."""
        # Manually set up the manager as active
        self.manager._active = True
        self.manager._client._registered = True
        self.manager._client._correlation_id = 'test-corr'
        self.manager._client.interaction_url = 'test-corr.test.oast.live'

        payloads = self.manager.get_oob_payloads('sqli', 'id', 'https://target.com/page')

        assert len(payloads) > 0
        for payload, callback_id in payloads:
            assert isinstance(payload, str)
            assert isinstance(callback_id, str)
            # Payload should NOT contain the raw {callback} placeholder
            assert '{callback}' not in payload

    def test_generate_oob_payloads_ssrf(self):
        """Test OOB payload generation for blind SSRF."""
        self.manager._active = True
        self.manager._client._registered = True
        self.manager._client._correlation_id = 'test-corr'
        self.manager._client.interaction_url = 'test-corr.test.oast.live'

        payloads = self.manager.get_oob_payloads('ssrf', 'url', 'https://target.com/page')

        assert len(payloads) > 0
        for payload, _ in payloads:
            assert 'test.oast.live' in payload or 'test-corr' in payload

    def test_generate_oob_payloads_xxe(self):
        """Test OOB payload generation for blind XXE."""
        self.manager._active = True
        self.manager._client._registered = True
        self.manager._client._correlation_id = 'test-corr'
        self.manager._client.interaction_url = 'test-corr.test.oast.live'

        payloads = self.manager.get_oob_payloads('xxe', 'xml', 'https://target.com/api')
        assert len(payloads) > 0

    def test_generate_oob_payloads_inactive(self):
        """Test that inactive manager returns empty payloads."""
        payloads = self.manager.get_oob_payloads('sqli', 'id', 'https://target.com')
        assert payloads == []

    def test_generate_oob_payloads_unknown_type(self):
        """Test unknown vuln type returns empty payloads."""
        self.manager._active = True
        self.manager._client._registered = True
        self.manager._client._correlation_id = 'test-corr'
        self.manager._client.interaction_url = 'test-corr.test.oast.live'

        payloads = self.manager.get_oob_payloads('unknown_vuln', 'x', 'https://target.com')
        assert payloads == []

    def test_payload_tracking(self):
        """Test that generated payloads are tracked for correlation."""
        self.manager._active = True
        self.manager._client._registered = True
        self.manager._client._correlation_id = 'test-corr'
        self.manager._client.interaction_url = 'test-corr.test.oast.live'

        self.manager.get_oob_payloads('sqli', 'id', 'https://target.com')
        assert self.manager.tracked_count > 0

    def test_poll_and_correlate_with_match(self):
        """Test OOB callback correlation when a match is found."""
        from apps.scanning.engine.oob.interactsh_client import Interaction

        self.manager._active = True
        self.manager._client._registered = True
        self.manager._client._correlation_id = 'test-corr'
        self.manager._client.interaction_url = 'test-corr.test.oast.live'

        # Generate a payload to get tracking data
        payloads = self.manager.get_oob_payloads('sqli', 'id', 'https://target.com')
        assert len(payloads) > 0

        # Get the first tracked key
        tracked_key = list(self.manager._tracking.keys())[0]

        # Simulate receiving a callback that matches
        mock_interaction = Interaction(
            protocol='dns',
            unique_id=tracked_key,
            full_id=f'{tracked_key}.test-corr.test.oast.live',
            raw_request='DNS query data',
            remote_address='10.0.0.1',
        )

        with patch.object(self.manager._client, 'poll', return_value=[mock_interaction]):
            findings = self.manager.poll_and_correlate(max_wait=1.0)

        assert len(findings) >= 1
        assert findings[0].vuln_type == 'sqli'
        assert findings[0].param_name == 'id'
        assert findings[0].target_url == 'https://target.com'

    def test_poll_and_correlate_no_callbacks(self):
        """Test OOB polling when no callbacks are received."""
        self.manager._active = True
        self.manager._client._registered = True
        self.manager._client._correlation_id = 'test-corr'
        self.manager._client.interaction_url = 'test-corr.test.oast.live'

        self.manager.get_oob_payloads('sqli', 'id', 'https://target.com')

        with patch.object(self.manager._client, 'poll', return_value=[]):
            findings = self.manager.poll_and_correlate(max_wait=1.0)

        assert findings == []

    def test_poll_and_correlate_empty_tracking(self):
        """Test that polling with nothing tracked returns immediately."""
        self.manager._active = True
        findings = self.manager.poll_and_correlate()
        assert findings == []

    def test_findings_to_vulns_sqli(self):
        """Test converting OOB findings to vulnerability dicts."""
        from apps.scanning.engine.oob.oob_manager import OOBFinding

        finding = OOBFinding(
            vuln_type='sqli',
            param_name='id',
            target_url='https://target.com/page?id=1',
            payload="'; EXEC xp_dirtree ...",
            callback_url='sqli-id-abc.test-corr.test.oast.live',
            callback_protocol='dns',
            callback_evidence='OOB callback received: dns from 10.0.0.1',
            remote_address='10.0.0.1',
        )

        vulns = self.manager.findings_to_vulns([finding])

        assert len(vulns) == 1
        vuln = vulns[0]
        assert vuln['name'] == 'Blind SQL Injection (OOB)'
        assert vuln['severity'] == 'critical'
        assert vuln['cwe'] == 'CWE-89'
        assert vuln['cvss'] == 9.8
        assert 'id' in vuln['evidence']
        assert vuln['oob_callback'] != ''

    def test_findings_to_vulns_ssrf(self):
        """Test converting SSRF OOB findings to vulnerability dicts."""
        from apps.scanning.engine.oob.oob_manager import OOBFinding

        finding = OOBFinding(
            vuln_type='ssrf',
            param_name='url',
            target_url='https://target.com/fetch?url=test',
            payload='http://callback.oast.live/ssrf',
            callback_url='ssrf-url-abc.test-corr.test.oast.live',
            callback_protocol='http',
            callback_evidence='HTTP callback received',
        )

        vulns = self.manager.findings_to_vulns([finding])
        assert len(vulns) == 1
        assert vulns[0]['severity'] == 'high'
        assert vulns[0]['cwe'] == 'CWE-918'

    def test_findings_to_vulns_rce(self):
        """Test converting RCE OOB findings to vulnerability dicts."""
        from apps.scanning.engine.oob.oob_manager import OOBFinding

        finding = OOBFinding(
            vuln_type='rce',
            param_name='cmd',
            target_url='https://target.com/exec?cmd=test',
            payload='`nslookup callback.oast.live`',
            callback_url='rce-cmd-abc.test.oast.live',
            callback_protocol='dns',
            callback_evidence='DNS callback received',
        )

        vulns = self.manager.findings_to_vulns([finding])
        assert len(vulns) == 1
        assert vulns[0]['severity'] == 'critical'
        assert vulns[0]['cvss'] == 10.0

    def test_stop_clears_state(self):
        """Test that stopping the manager clears all state."""
        self.manager._active = True
        self.manager._tracking['test'] = 'dummy'

        with patch.object(self.manager._client, 'close'):
            self.manager.stop()

        assert self.manager.is_active is False
        assert self.manager.tracked_count == 0


# ═══════════════════════════════════════════════════════════════════════════
# CallbackServer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCallbackServer:
    """Test suite for the fallback CallbackServer."""

    def setup_method(self):
        from apps.scanning.engine.oob.callback_server import CallbackServer
        self.server = CallbackServer(base_domain='test.oast.live')

    def test_generate_canary(self):
        """Test canary token generation."""
        canary = self.server.generate_canary('sqli', 'id', 'https://target.com')

        assert canary.token is not None
        assert 'test.oast.live' in canary.token
        assert canary.vuln_type == 'sqli'
        assert canary.param_name == 'id'
        assert self.server.canary_count == 1

    def test_generate_unique_canaries(self):
        """Test that canaries are unique per call."""
        c1 = self.server.generate_canary('sqli', 'id', 'https://target.com')
        c2 = self.server.generate_canary('sqli', 'id', 'https://target.com')

        assert c1.token != c2.token
        assert self.server.canary_count == 2

    def test_check_canary_match(self):
        """Test canary token matching."""
        canary = self.server.generate_canary('ssrf', 'url', 'https://target.com')
        # Extract the hash part from the token
        canary.token.split('.')[0].split('-')[-1]

        result = self.server.check_canary(canary.token)
        assert result is not None
        assert result.vuln_type == 'ssrf'
        assert result.param_name == 'url'

    def test_check_canary_no_match(self):
        """Test canary check returns None for unknown domains."""
        self.server.generate_canary('sqli', 'id', 'https://target.com')

        result = self.server.check_canary('nonexistent.example.com')
        assert result is None

    def test_clear_canaries(self):
        """Test clearing all canaries."""
        self.server.generate_canary('sqli', 'id', 'https://target.com')
        self.server.generate_canary('ssrf', 'url', 'https://target.com')
        assert self.server.canary_count == 2

        self.server.clear()
        assert self.server.canary_count == 0


# ═══════════════════════════════════════════════════════════════════════════
# OOB Payload Template Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestOOBPayloadTemplates:
    """Test suite for OOB payload templates and their generation."""

    def test_sqli_payload_templates_exist(self):
        """Test that blind SQLi OOB payload templates are defined."""
        from apps.scanning.engine.oob.oob_manager import BLIND_SQLI_OOB_PAYLOADS
        assert len(BLIND_SQLI_OOB_PAYLOADS) >= 5
        for payload in BLIND_SQLI_OOB_PAYLOADS:
            assert '{callback}' in payload

    def test_ssrf_payload_templates_exist(self):
        """Test that blind SSRF OOB payload templates are defined."""
        from apps.scanning.engine.oob.oob_manager import BLIND_SSRF_OOB_PAYLOADS
        assert len(BLIND_SSRF_OOB_PAYLOADS) >= 3
        for payload in BLIND_SSRF_OOB_PAYLOADS:
            assert '{callback}' in payload

    def test_xxe_payload_templates_exist(self):
        """Test that blind XXE OOB payload templates are defined."""
        from apps.scanning.engine.oob.oob_manager import BLIND_XXE_OOB_PAYLOADS
        assert len(BLIND_XXE_OOB_PAYLOADS) >= 2
        for payload in BLIND_XXE_OOB_PAYLOADS:
            assert '{callback}' in payload

    def test_rce_payload_templates_exist(self):
        """Test that blind RCE OOB payload templates are defined."""
        from apps.scanning.engine.oob.oob_manager import BLIND_RCE_OOB_PAYLOADS
        assert len(BLIND_RCE_OOB_PAYLOADS) >= 5
        for payload in BLIND_RCE_OOB_PAYLOADS:
            assert '{callback}' in payload

    def test_ssti_payload_templates_exist(self):
        """Test that blind SSTI OOB payload templates are defined."""
        from apps.scanning.engine.oob.oob_manager import BLIND_SSTI_OOB_PAYLOADS
        assert len(BLIND_SSTI_OOB_PAYLOADS) >= 2

    def test_oob_vuln_metadata_all_types(self):
        """Test that vulnerability metadata is defined for all OOB types."""
        from apps.scanning.engine.oob.oob_manager import OOB_VULN_METADATA
        required_types = ['sqli', 'ssrf', 'xxe', 'rce', 'cmdi', 'ssti']
        for vuln_type in required_types:
            assert vuln_type in OOB_VULN_METADATA
            meta = OOB_VULN_METADATA[vuln_type]
            assert 'name' in meta
            assert 'severity' in meta
            assert 'cwe' in meta
            assert 'cvss' in meta
            assert meta['severity'] in ('critical', 'high', 'medium', 'low', 'info')

    def test_oob_payload_map_completeness(self):
        """Test that OOB_PAYLOAD_MAP covers all key vuln types."""
        from apps.scanning.engine.oob.oob_manager import OOB_PAYLOAD_MAP
        required = ['sqli', 'ssrf', 'xxe', 'rce', 'cmdi', 'ssti']
        for key in required:
            assert key in OOB_PAYLOAD_MAP
            assert len(OOB_PAYLOAD_MAP[key]) > 0


# ═══════════════════════════════════════════════════════════════════════════
# BaseTester OOB Helper Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestBaseTesterOOBHelpers:
    """Test OOB helper methods added to BaseTester."""

    def setup_method(self):
        from apps.scanning.engine.testers.base_tester import BaseTester
        self.tester = BaseTester()

    def test_get_oob_manager_from_recon_data(self):
        """Test extracting OOB manager from recon_data."""
        mock_manager = MagicMock()
        recon_data = {'_oob_manager': mock_manager}
        result = self.tester._get_oob_manager(recon_data)
        assert result is mock_manager

    def test_get_oob_manager_none_when_missing(self):
        """Test OOB manager returns None when not in recon_data."""
        assert self.tester._get_oob_manager(None) is None
        assert self.tester._get_oob_manager({}) is None

    def test_get_oob_payloads_delegates_to_manager(self):
        """Test that _get_oob_payloads delegates to the OOB manager."""
        mock_manager = MagicMock()
        mock_manager.get_oob_payloads.return_value = [('payload1', 'cb1')]
        recon_data = {'_oob_manager': mock_manager}

        result = self.tester._get_oob_payloads('sqli', 'id', 'https://target.com', recon_data)

        assert result == [('payload1', 'cb1')]
        mock_manager.get_oob_payloads.assert_called_once_with('sqli', 'id', 'https://target.com')

    def test_get_oob_payloads_empty_when_no_manager(self):
        """Test empty payloads when OOB manager unavailable."""
        result = self.tester._get_oob_payloads('sqli', 'id', 'https://target.com', None)
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════
# Tester OOB Integration Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestTesterOOBIntegration:
    """Test that testers correctly inject OOB payloads."""

    def _make_page(self, params=None):
        return MockPage(
            url='https://example.com/search?q=test',
            parameters=params or {'q': 'test'},
            body='<html><body>Safe</body></html>',
            headers={'Content-Type': 'text/html'},
        )

    def test_sqli_tester_injects_oob(self):
        """Test SQLi tester injects OOB payloads when manager is active."""
        from apps.scanning.engine.testers.sqli_tester import SQLInjectionTester
        tester = SQLInjectionTester()

        mock_manager = MagicMock()
        mock_manager.get_oob_payloads.return_value = [
            ('oob_payload_1', 'cb1'), ('oob_payload_2', 'cb2')]
        recon_data = {'_oob_manager': mock_manager}

        safe_resp = MagicMock()
        safe_resp.status_code = 200
        safe_resp.text = 'Safe response'
        safe_resp.content = b'Safe response'
        safe_resp.headers = {}
        safe_resp.url = 'https://example.com/search'
        safe_resp.elapsed = MagicMock()
        safe_resp.elapsed.total_seconds.return_value = 0.1
        safe_resp.cookies = {}
        safe_resp.ok = True

        page = self._make_page()

        with patch.object(tester, '_make_request', return_value=safe_resp):
            results = tester.test(page, depth='medium', recon_data=recon_data)

        # OOB payloads should be requested (manager.get_oob_payloads called)
        mock_manager.get_oob_payloads.assert_called()
        assert isinstance(results, list)

    def test_ssrf_tester_injects_oob(self):
        """Test SSRF tester injects OOB payloads for URL params."""
        from apps.scanning.engine.testers.ssrf_tester import SSRFTester
        tester = SSRFTester()

        mock_manager = MagicMock()
        mock_manager.get_oob_payloads.return_value = [('http://oob.oast.live/ssrf', 'cb1')]
        recon_data = {'_oob_manager': mock_manager}

        safe_resp = MagicMock()
        safe_resp.status_code = 200
        safe_resp.text = 'Safe'
        safe_resp.content = b'Safe'
        safe_resp.headers = {}
        safe_resp.url = 'https://example.com'
        safe_resp.elapsed = MagicMock()
        safe_resp.elapsed.total_seconds.return_value = 0.1
        safe_resp.cookies = {}
        safe_resp.ok = True

        page = self._make_page({'url': 'https://example.com'})

        with patch.object(tester, '_make_request', return_value=safe_resp):
            results = tester.test(page, depth='medium', recon_data=recon_data)

        mock_manager.get_oob_payloads.assert_called()
        assert isinstance(results, list)

    def test_tester_no_crash_without_oob(self):
        """Test testers work fine without OOB manager (backward compatible)."""
        from apps.scanning.engine.testers.sqli_tester import SQLInjectionTester
        tester = SQLInjectionTester()

        safe_resp = MagicMock()
        safe_resp.status_code = 200
        safe_resp.text = 'Safe response'
        safe_resp.content = b'Safe response'
        safe_resp.headers = {}
        safe_resp.url = 'https://example.com'
        safe_resp.elapsed = MagicMock()
        safe_resp.elapsed.total_seconds.return_value = 0.1
        safe_resp.cookies = {}
        safe_resp.ok = True

        page = self._make_page()

        with patch.object(tester, '_make_request', return_value=safe_resp):
            results = tester.test(page, depth='medium', recon_data=None)

        assert isinstance(results, list)

    def test_tester_oob_with_timeout(self):
        """Test tester handles OOB injection even when requests timeout."""
        from apps.scanning.engine.testers.cmdi_tester import CommandInjectionTester
        tester = CommandInjectionTester()

        mock_manager = MagicMock()
        mock_manager.get_oob_payloads.return_value = [('`nslookup x.oast`', 'cb1')]
        recon_data = {'_oob_manager': mock_manager}

        page = self._make_page({'cmd': 'test'})

        with patch.object(tester, '_make_request', return_value=None):
            results = tester.test(page, depth='medium', recon_data=recon_data)

        assert isinstance(results, list)


# ═══════════════════════════════════════════════════════════════════════════
# OOB Timeout Handling Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestOOBTimeoutHandling:
    """Test OOB timeout and edge case handling."""

    def test_poll_respects_max_wait(self):
        """Test that polling doesn't exceed max_wait."""
        from apps.scanning.engine.oob.oob_manager import OOBManager

        manager = OOBManager(poll_interval=0.1, poll_timeout=0.5)
        manager._active = True
        manager._client._registered = True
        manager._client._correlation_id = 'test'
        manager._client.interaction_url = 'test.oast.live'

        manager.get_oob_payloads('sqli', 'id', 'https://target.com')

        start = time.monotonic()
        with patch.object(manager._client, 'poll', return_value=[]):
            findings = manager.poll_and_correlate(max_wait=0.5)
        elapsed = time.monotonic() - start

        assert findings == []
        # Should complete within a reasonable time (poll_timeout + buffer)
        assert elapsed < 3.0

    def test_oob_manager_interaction_url_property(self):
        """Test interaction_url property."""
        from apps.scanning.engine.oob.oob_manager import OOBManager

        manager = OOBManager()
        assert manager.interaction_url is None

        manager._client.interaction_url = 'test.oast.live'
        assert manager.interaction_url == 'test.oast.live'
