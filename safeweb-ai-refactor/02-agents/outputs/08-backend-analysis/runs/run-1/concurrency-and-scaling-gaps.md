---
Source agent: Backend Analysis Agent
Run date: 2026-06-23
Inputs used: repo-map.md, integration-points.md, current-architecture-assessment.md, backend/apps/scanning/views.py, backend/apps/scanning/engine/orchestrator.py
Status: draft
---

# Concurrency and Scaling Gaps

| Issue | Component | What breaks under concurrent multi-tenant load | BE-NNN | Severity |
|-------|-----------|------------------------------------------------|--------|----------|
| Missing API Versioning | `backend/apps/scanning/views.py` | Breaking API changes will impact all tenants simultaneously. | BE-001 | Medium |
| In-Memory Fallback Threading | `views.py (_dispatch_scan_task)` | If Celery is unreachable, threads are spawned directly in the web server process, risking RAM exhaustion and worker crashes under heavy multi-tenant load. | BE-002 | High |
| Subprocess Resource Exhaustion | `tools/base.py` | Spawning numerous heavy CLI tools (`nuclei`) per scan could exhaust system resources (CPU/RAM/File Descriptors) when dozens of scans run concurrently. | BE-003 | High |
