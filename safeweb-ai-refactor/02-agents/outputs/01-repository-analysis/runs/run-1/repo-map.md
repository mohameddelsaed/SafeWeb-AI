---
Source agent: Repository Analysis Agent
Run date: 2026-06-23
Inputs used: Full clone of safeweb-ai, SAFEWEB_AI_CODEBASE_BOOK.md, src/services/api.ts, backend/apps/scanning/engine/tools/base.py
Status: draft
---

# Repository Map

## Root Level
- `package.json`, `vite.config.ts`, `tailwind.config.js`: Frontend build and configuration (Node/Vite).
- `nixpacks.toml`, `railway.toml`, `vercel.json`: Deployment manifests (TOML/JSON).
- `SAFEWEB_AI_CODEBASE_BOOK.md`: Core repository documentation.

## Backend (`backend/`)
- `backend/manage.py`, `backend/Procfile`, `backend/requirements.txt`: Backend entry points (Python/Django).
- `backend/config/`: Django project settings, WSGI/ASGI entry points. `urls.py` acts as top-level router.
- `backend/celery_app.py`: Celery instance and background task configuration.
- `backend/apps/accounts/`: Identity and access management (Python). Entry points: `views.py`.
- `backend/apps/scanning/`: Core product domain for scanning. `views.py` holds operational endpoints.
  - `backend/apps/scanning/engine/orchestrator.py`: Main scan execution coordinator.
  - `backend/apps/scanning/engine/crawler.py`: Target discovery and crawling.
  - `backend/apps/scanning/engine/testers/base_tester.py`: Abstract superclass for vulnerability modules.
  - `backend/apps/scanning/engine/tools/base.py`: External tool wrappers.
- `backend/apps/chatbot/`: Assistant domain and LLM orchestration (Python). `engine.py` is the orchestrator.
- `backend/apps/ml/`: Preserved machine learning models for phishing/malware (Python).
- `backend/apps/admin_panel/`: Internal operations plane (Python).
- `backend/apps/learn/`: Content subsystem for educational articles (Python).

## Frontend (`src/`)
- `src/main.tsx`: React application mount point.
- `src/App.tsx`: Top-level route shell and layout container.
- `src/index.css`: Global visual styling entry point.
- `src/services/api.ts`: API client configuration and interceptors (TypeScript).
- `src/contexts/AuthContext.tsx`: Authentication state management.
- `src/pages/`: Directory of view-level React components (e.g., `ScanWebsite.tsx`, `ScanResults.tsx`).
- `src/components/`: Reusable UI elements and layout segments.

## Tooling and Scripts
- `scripts/`: Local operator setup scripts (e.g., `install-tools.ps1`).
- `tools/`: External security binaries and supporting assets.
