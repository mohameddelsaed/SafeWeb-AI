# 07 - AI Provider Gateway Test Suite

## Objective
Validate the fallback mechanisms, token masking, and organization-level overrides of the LLM Engine.

## Scope
- `AIConfiguration` Key Masking
- Provider Fallback Logic (OpenRouter -> Custom)

## Specifications
1. **Key Masking**:
   - Setup: Save `sk-1234567890abcdef`.
   - Action: GET `/api/v1/user/settings/`.
   - Assert: Response contains `sk-...cdef`.
2. **Fallback Simulation**:
   - Setup: Mock OpenAI API to return 503 Service Unavailable.
   - Action: Trigger `populate_ai_explanations_task`.
   - Assert: System falls back to Anthropic provider seamlessly.

## AI Prompt Instructions
"Use `responses` library to mock external LLM calls. Induce HTTP 500s on the primary provider and assert the `LLMProvider` class gracefully fails over."\n