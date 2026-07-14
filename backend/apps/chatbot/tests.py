import pytest
from apps.chatbot.engine import ChatEngine

@pytest.mark.unit
class TestChatEngine:
    def test_llm_suggestions_generation(self):
        """Test basic local response fallback."""
        engine = ChatEngine()
        
        # Test basic local response fallback
        response = engine._local_response("How do I start a scan?")
        assert "Starting a Security Scan" in response['response']
        assert "suggestions" in response

    def test_llm_json_extractor(self):
        """Pass dirty markdown strings to the extractor and assert clean dict return."""
        engine = ChatEngine()
        dirty_json = """Here is your data:
```json
{
  "key": "value"
}
```
Hope this helps!"""
        clean_dict = engine.extract_json(dirty_json)
        assert clean_dict == {"key": "value"}
