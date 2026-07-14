import pytest
import responses
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from apps.accounts.models import Organization, OrganizationMembership, AIConfiguration
from apps.scanning.engine.ai.provider import LLMProvider

User = get_user_model()
pytestmark = pytest.mark.django_db(transaction=True)

@pytest.fixture
def auth_client(django_user_model):
    user = django_user_model.objects.create_user(
        email='ai_admin@example.com',
        username='ai_admin@example.com',
        password='password123!',
        name='AI Admin'
    )
    org = Organization.objects.create(name='AI Org')
    OrganizationMembership.objects.create(
        user=user,
        organization=org,
        role='owner'
    )
    AIConfiguration.objects.create(
        organization=org,
        provider='openai',
        api_key='sk-1234567890abcdef',
        model_name='gpt-4'
    )
    
    client = APIClient()
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(user)
    client.credentials(
        HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}',
        HTTP_X_ORGANIZATION_ID=str(org.id)
    )
    client.force_authenticate(user=user)
    return client

from unittest.mock import patch

def test_ai_configuration_key_masking(auth_client):
    """
    Test Key Masking:
    Assert response contains masked key.
    """
    from apps.accounts.serializers import AIConfigurationSerializer
    config = AIConfiguration.objects.first()
    serializer = AIConfigurationSerializer(config)
    assert serializer.data['api_key'] == 'sk-...cdef'

@responses.activate
def test_provider_fallback_logic():
    """
    Test Fallback Simulation:
    Mock OpenAI API to return 503.
    Trigger generate_json in LLMProvider.
    Assert: System falls back to Ollama gracefully.
    """
    # Setup OpenAI 503 response
    responses.add(
        responses.POST,
        "https://api.openai.com/v1/chat/completions",
        json={"error": "Service Unavailable"},
        status=503
    )

    # Need to set an org context so LLMProvider loads the config we create
    org = Organization.objects.create(name='Test Fallback Org')
    AIConfiguration.objects.create(
        organization=org,
        provider='openai',
        api_key='sk-testkey',
        model_name='gpt-4'
    )
    
    with patch('apps.accounts.middleware.get_current_organization', return_value=org):
        with patch('apps.scanning.engine.ai.ollama_client.OllamaClient.generate_json', return_value={"result": "fallback_success"}) as mock_ollama:
            with patch('apps.scanning.engine.ai.ollama_client.OllamaClient.is_available', return_value=True):
                provider = LLMProvider()
                result = provider.generate_json("Test prompt", system="Test system")
                
                assert mock_ollama.called
                assert result == {"result": "fallback_success"}
