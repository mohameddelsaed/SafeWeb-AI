---
Source agent: AI Workflow Analysis Agent
Run date: 2026-06-23
Inputs used: repo-map.md, backend/apps/chatbot/engine.py, 01-research/ai-provider-research/
Status: draft
---

# Prompt Management Review

- **Location**: Prompts are defined as hardcoded string constants within the Python source code (e.g., `SYSTEM_PROMPT` in `backend/apps/chatbot/engine.py`).
- **Versioning**: There is no dedicated prompt versioning system or external Content Management System (CMS). Prompt revisions are tracked solely via git commits to the `engine.py` file.
- **Structure**: The system prompt is comprehensive, including explicit platform knowledge (scan types, score calculations) and strict anti-injection rules instructing the LLM to ignore `<user_message>` tags.
