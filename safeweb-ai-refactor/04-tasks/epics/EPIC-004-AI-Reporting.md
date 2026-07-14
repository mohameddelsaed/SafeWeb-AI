# EPIC-004: AI & Reporting Pipeline

## Description
Abstracts AI providers and powers the non-specialist reporting engine.

## Features & Tasks

### Feature 1: AI Provider Abstraction (Phase 5)
- **Cites:** `04-ai-pipeline-spec.md §3.1 (REQ-AI-001)`
- **Task 1.1:** Build standard LLM interfaces wrapping OpenRouter and Ollama.
- **Task 1.2:** Extract all hardcoded prompts into a versioned registry.

### Feature 2: Plain-Language Reporting (Phase 5)
- **Cites:** `05-reporting-engine-spec.md §3.1 (REQ-REP-001)`
- **Task 2.1:** Integrate the AI pipeline to summarize scanner findings.
- **Task 2.2:** Build the PDF export functionality for summarized reports.
