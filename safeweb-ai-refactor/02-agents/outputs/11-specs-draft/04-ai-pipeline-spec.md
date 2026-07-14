---
Spec ID: 04-ai-pipeline-spec
Version: 1.0
Status: draft
Source agent: Spec Generation Agent
Run date: 2026-06-23
Supersedes: none
---

## 1. Purpose & Scope
Governs the integration of AI providers, prompt management, and fallback strategies. It does NOT govern how AI output is displayed in the UI.

## 2. Findings Addressed
| Finding ID | Source Agent | How This Spec Resolves It |
|---|---|---|
| AI-001 | AI Agent | Extracts prompts from code into a versioned registry (REQ-AI-002). |

## 3. Requirements
### 3.1 Functional Requirements
- REQ-AI-001: The system shall use an abstraction layer for LLM providers, defaulting to OpenRouter (free tier).
- REQ-AI-002: Prompts must be centrally managed and versioned, not hardcoded into Python files.
- REQ-AI-003: If OpenRouter is unavailable, the system must gracefully fall back to a local Ollama instance or keyword heuristic.

### 3.2 Non-Functional Requirements
- REQ-AI-NFR-001: AI queries must support streaming for immediate UI feedback.

## 4. Out of Scope
- Reporting dashboard UI.

## 5. Dependencies
- Depends on: 01-architecture-spec
- Depended on by: 05-reporting-engine-spec

## 6. Open Questions / Decisions Needed
- None

## 7. Acceptance Criteria
Can swap LLM providers without altering core application code.

## 8. Change Log
| Version | Date | What changed | Why |
|---|---|---|---|
| 1.0 | 2026-06-23 | Initial draft | Agent 11 execution |
