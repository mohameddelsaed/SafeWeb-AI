---
Source agent: Architecture Analysis Agent
Run date: 2026-06-23
Inputs used: repo-map.md, integration-points.md, multi-tenancy-patterns.md
Status: draft
---

# Technology Stack Review

- **Frontend**: React, TypeScript, Vite, Tailwind CSS. Chosen for rich interactivity and component-based UI.
- **Backend**: Django, Django REST Framework (Python). Chosen for rapid API development, built-in admin, and robust ORM.
- **Background Processing**: Celery with Redis broker. Chosen for asynchronous, distributed task execution (critical for long-running scans).
- **Database**: PostgreSQL (production) / SQLite (development). Standard relational storage suitable for structured scan/finding data.
- **External Dependencies**: Local security binaries (e.g., Nuclei). These dictate that the deployment environment must support host-level execution (e.g., via Docker or Nixpacks).
- **Multi-Tenancy**: The application uses a shared database and shared schema model. Tenant isolation is managed strictly via Django ORM query constraints (e.g., filtering by `user_id`).
