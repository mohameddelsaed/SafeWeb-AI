---
Source agent: AI Workflow Analysis Agent
Run date: 2026-06-23
Inputs used: repo-map.md, backend/apps/chatbot/engine.py, 01-research/ai-provider-research/
Status: draft
---

# LLM Provider Integration Review

- **Provider**: OpenRouter (acting as a proxy to various models).
- **Client Library**: Uses the official `openai` Python package, overriding `base_url` to `https://openrouter.ai/api/v1`.
- **Model**: Driven by `settings.OPENROUTER_MODEL`, defaulting to `google/gemini-2.0-flash-001`.
- **Capabilities**: Leverages OpenAI-compatible function calling (defined in `ACTION_TOOLS`) to allow the LLM to trigger scans, fetch results, and navigate the user UI.
- **Resiliency**: The `ChatEngine` class implements a graceful fallback mechanism. If the OpenRouter API key is missing or the network call fails, it routes the message to `_local_response`, which performs keyword/bigram matching against a hardcoded local Knowledge Base.
