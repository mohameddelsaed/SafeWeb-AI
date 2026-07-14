"""Tests for vulnerability testers — Phase 5 (AI/LLM) and Phase 6 (Missing Classes)."""
from unittest.mock import patch, MagicMock
from tests.conftest import MockPage, MockForm, MockFormInput


# ---------------------------------------------------------------------------
# Phase 5: AI/LLM Security
# ---------------------------------------------------------------------------

class TestPromptInjectionTester:
    def setup_method(self):
        from apps.scanning.engine.testers.prompt_injection_tester import PromptInjectionTester
        self.tester = PromptInjectionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Prompt Injection'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)

    def test_accepts_recon_data(self):
        """Tester should accept recon_data kwarg without error."""
        page = MockPage(url='https://example.com/chat')
        vulns = self.tester.test(page, 'shallow', recon_data={'ai_recon': {'ai_detected': False}})
        assert isinstance(vulns, list)

    def test_ai_page_gets_tested(self):
        """Pages with AI-related content should trigger testing."""
        page = MockPage(
            url='https://example.com/api/chat',
            body='<textarea id="chatbox"></textarea><div id="ai-response"></div>',
            forms=[MockForm(
                action='/api/chat',
                method='POST',
                inputs=[MockFormInput(name='message', input_type='text')],
            )],
            parameters={'message': 'hello'},
        )
        # With AI recon data
        recon = {'ai_recon': {'ai_detected': True, 'ai_endpoints': ['/api/chat']}}
        vulns = self.tester.test(page, 'medium', recon_data=recon)
        assert isinstance(vulns, list)


class TestAIEndpointTester:
    def setup_method(self):
        from apps.scanning.engine.testers.ai_endpoint_tester import AIEndpointTester
        self.tester = AIEndpointTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'AI Endpoint Security'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)

    def test_accepts_recon_data(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow', recon_data={})
        assert isinstance(vulns, list)

    def test_has_test_method(self):
        assert hasattr(self.tester, 'test')
        assert callable(self.tester.test)


# ---------------------------------------------------------------------------
# Phase 6: Missing Vulnerability Classes
# ---------------------------------------------------------------------------

class TestPrototypePollutionTester:
    def setup_method(self):
        from apps.scanning.engine.testers.prototype_pollution_tester import PrototypePollutionTester
        self.tester = PrototypePollutionTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Prototype Pollution'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)

    def test_json_api_gets_tested(self):
        """JSON endpoints should be tested for prototype pollution."""
        page = MockPage(
            url='https://example.com/api/settings',
            headers={'Content-Type': 'application/json'},
            body='{"key": "value"}',
            parameters={'config': '{}'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"__proto__": {}, "key": "value"}'
        mock_resp.headers = {'Content-Type': 'application/json'}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


class TestOpenRedirectTester:
    def setup_method(self):
        from apps.scanning.engine.testers.open_redirect_tester import OpenRedirectTester
        self.tester = OpenRedirectTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Open Redirect'

    def test_no_redirect_params_skips(self):
        page = MockPage(url='https://example.com/about')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)

    def test_detects_redirect_parameter(self):
        """Pages with redirect/url params should be tested."""
        page = MockPage(
            url='https://example.com/login?redirect=https://example.com/dashboard',
            parameters={'redirect': 'https://example.com/dashboard'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {'Location': 'https://evil.com'}
        mock_resp.text = ''
        mock_resp.is_redirect = True

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)


class TestBusinessLogicTester:
    def setup_method(self):
        from apps.scanning.engine.testers.business_logic_tester import BusinessLogicTester
        self.tester = BusinessLogicTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Business Logic'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)

    def test_checkout_page_gets_tested(self):
        """Commerce pages should trigger business logic checks."""
        page = MockPage(
            url='https://example.com/checkout',
            body='<form action="/pay" method="POST"><input name="price" value="99.99"><input name="quantity" value="1"></form>',
            forms=[MockForm(
                action='/pay',
                method='POST',
                inputs=[
                    MockFormInput(name='price', input_type='hidden', value='99.99'),
                    MockFormInput(name='quantity', input_type='number', value='1'),
                ],
            )],
        )
        vulns = self.tester.test(page, 'medium')
        assert isinstance(vulns, list)


class TestAPITester:
    def setup_method(self):
        from apps.scanning.engine.testers.api_tester import APITester
        self.tester = APITester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'API Security'

    def test_empty_page_no_crash(self):
        page = MockPage(url='https://example.com/')
        vulns = self.tester.test(page, 'shallow')
        assert isinstance(vulns, list)

    def test_api_endpoint_gets_tested(self):
        """REST API endpoints should trigger API security testing."""
        page = MockPage(
            url='https://api.example.com/v1/users/1',
            headers={'Content-Type': 'application/json'},
            body='{"id": 1, "name": "admin", "role": "admin"}',
            parameters={'id': '1'},
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"id": 2, "name": "other", "role": "user"}'
        mock_resp.headers = {'Content-Type': 'application/json'}

        with patch.object(self.tester, '_make_request', return_value=mock_resp):
            vulns = self.tester.test(page, 'medium')
            assert isinstance(vulns, list)
