---
Source agent: Repository Analysis Agent
Run date: 2026-06-23
Inputs used: Full clone of safeweb-ai, SAFEWEB_AI_CODEBASE_BOOK.md, src/services/api.ts, backend/apps/scanning/engine/tools/base.py
Status: draft
---

# Integration Points

| Source Component | Target Component | Mechanism | Evidence |
|------------------|------------------|-----------|----------|
| Frontend React (`src/`) | Backend Django API (`backend/apps/`) | HTTP REST over Axios | `src/services/api.ts:4` |
| Frontend Auth Interceptor | Backend Token Refresh API | HTTP REST with 401 interceptor | `src/services/api.ts:39` |
| Django Settings | PostgreSQL / SQLite | Database connection strings | `backend/config/settings/base.py` |
| Django `scanning` App | Redis / Celery Workers | Async message queue via Celery | `backend/celery_app.py`, `backend/apps/scanning/tasks.py` |
| Scanning Orchestrator | Base Tester Modules | Direct Python instantiation / callbacks | `backend/apps/scanning/engine/orchestrator.py` |
| External Tool Wrapper | Host System CLI (e.g., `nuclei`, `nmap`) | Subprocess execution | `backend/apps/scanning/engine/tools/base.py:110` |
| Backend Server | Frontend UI | Server-Sent Events (SSE) for progress streaming | `backend/apps/scanning/views.py` |
