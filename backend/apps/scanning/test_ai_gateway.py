import pytest
import responses
from django.test import TestCase
from unittest.mock import patch
from apps.accounts.models import AIConfiguration, Organization, User
from apps.scanning.engine.ai.provider import LLMProvider

@pytest.mark.django_db
class TestAIGateway(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='user@test.com', username='user@test.com', password='Password123!')
        self.org = Organization.objects.create(name='Test Org')
        self.config = AIConfiguration.objects.create(
            organization=self.org,
            provider='openai',
            api_key='sk-1234567890abcdef',
            base_url='https://api.openai.com/v1/chat/completions'
        )

    def test_key_masking(self):
        """Test AIConfiguration Key Masking"""
        self.assertEqual(self.config.masked_api_key, 'sk-...cdef')

    @responses.activate
    @patch('apps.scanning.engine.ai.provider.get_current_organization', create=True)
    @patch('apps.scanning.engine.ai.provider.OllamaClient')
    def test_provider_fallback(self, mock_ollama, mock_get_org):
        """Test Provider Fallback Logic"""
        mock_get_org.return_value = self.org
        mock_ollama_instance = mock_ollama.return_value
        mock_ollama_instance.is_available.return_value = True
        mock_ollama_instance.generate_json.return_value = {"status": "ollama_fallback"}
        
        provider = LLMProvider()
        
        # Mock OpenAI to fail
        responses.add(
            responses.POST,
            'https://api.openai.com/v1/chat/completions',
            json={'error': 'Service Unavailable'},
            status=503
        )
        
        result = provider.generate_json(prompt="Test prompt")
        
        # Verify it fell back to Ollama
        self.assertEqual(result, {"status": "ollama_fallback"})
        mock_ollama_instance.generate_json.assert_called_once()
