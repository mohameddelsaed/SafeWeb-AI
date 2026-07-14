# Summary for Next Agent

The AI Workflow Analysis Agent verified that the Chatbot relies on the OpenRouter API (using the `openai` Python SDK with an overridden `base_url`). Prompts are hardcoded in `engine.py` rather than an external CMS. It supports LLM function calling and gracefully degrades to a hardcoded local Knowledge Base if the API is unreachable.
