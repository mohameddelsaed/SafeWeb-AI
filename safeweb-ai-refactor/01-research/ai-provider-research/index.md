# AI Provider Research

## Overview
SafeWeb AI uses LLMs for the chatbot and vulnerability reasoning.

## Providers
- **OpenAI**: Primary provider for high-reasoning tasks.
- **OpenRouter**: Used as a fallback/routing layer (e.g., `google/gemini-2.0-flash-001`).

## Integration Approach
- Use native API clients or standard REST requests.
- Ensure API keys are stored securely in `.env`.
- Implement graceful degradation if the AI provider is unavailable or rate-limited.
