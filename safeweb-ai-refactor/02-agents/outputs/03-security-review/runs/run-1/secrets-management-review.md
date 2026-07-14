---
Source agent: Security Review Agent
Run date: 2026-06-23
Inputs used: src/services/api.ts, backend/config/settings/base.py, backend/apps/accounts/models.py, backend/apps/scanning/views.py
Status: draft
---

# Secrets Management Review

- **Environment Variables**: Loaded via `python-dotenv` from `.env`.
- **Key Storage**: `SECRET_KEY`, Database/Redis URIs, and third-party API keys (OpenAI, Shodan, Censys, VirusTotal, GitHub) are sourced exclusively from environment variables in `backend/config/settings/base.py`.
- **User API Keys**: Programmatic access keys (`APIKey` model) are generated using `secrets.token_hex(24)` and stored in the database.
- **Hardcoded Secrets**: No hardcoded secrets were found in the inspected configuration files; fallbacks (e.g., `'django-insecure-safeweb-dev-key'`) exist only for local development defaults.
