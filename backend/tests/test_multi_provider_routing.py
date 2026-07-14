from unittest.mock import patch, MagicMock
from apps.scanning.engine.ai.provider import LLMProvider

def test_multi_provider_routing_unit():
    """
    Unit Test for 10 AI Providers routing and default models without requiring DB connection.
    """
    providers_expected = {
        'openai': ("https://api.openai.com/v1/chat/completions", "gpt-4o-mini"),
        'gemini': ("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "gemini-2.5-flash"),
        'groq': ("https://api.groq.com/openai/v1/chat/completions", "llama-3.3-70b-versatile"),
        'openrouter': ("https://openrouter.ai/api/v1/chat/completions", "openai/gpt-3.5-turbo"),
        'cerebras': ("https://api.cerebras.ai/v1/chat/completions", "llama3.1-70b"),
        'mistral': ("https://api.mistral.ai/v1/chat/completions", "mistral-large-latest"),
        'together': ("https://api.together.ai/v1/chat/completions", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
        'fireworks': ("https://api.fireworks.ai/inference/v1/chat/completions", "accounts/fireworks/models/llama-v3p3-70b-instruct"),
        'xai': ("https://api.x.ai/v1/chat/completions", "grok-2-1212"),
        'anthropic': ("https://api.anthropic.com/v1/messages", "claude-3-5-sonnet-20241022"),
    }

    with patch('apps.accounts.middleware.get_current_organization', return_value=None):
        provider = LLMProvider()
        for prov_name, (expected_url, expected_model) in providers_expected.items():
            mock_cfg = MagicMock()
            mock_cfg.api_key = "sk-mock-key"
            mock_cfg.base_url = ""
            mock_cfg.model_name = ""
            mock_cfg.provider = prov_name
            provider.org_config = mock_cfg

            url, headers, model = provider._get_api_headers_and_url()
            assert url == expected_url, f"Failed URL check for {prov_name}"
            assert model == expected_model, f"Failed model check for {prov_name}"
            if prov_name == 'anthropic':
                assert headers.get("x-api-key") == "sk-mock-key"
                assert "Authorization" not in headers
            elif prov_name == 'openrouter':
                assert headers.get("Authorization") == "Bearer sk-mock-key"
                assert headers.get("HTTP-Referer") == "https://safeweb-ai.com"
                assert headers.get("X-Title") == "SafeWeb AI"
            else:
                assert headers.get("Authorization") == "Bearer sk-mock-key"
