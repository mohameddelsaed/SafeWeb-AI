---
Source agent: Backend Analysis Agent
Run date: 2026-06-23
Inputs used: repo-map.md, integration-points.md, current-architecture-assessment.md, backend/apps/scanning/views.py, backend/apps/scanning/engine/orchestrator.py
Status: draft
---

# Backend Assessment

## Execution Model
- **Trigger Mechanism**: The API layer initiates scans asynchronously. `_dispatch_scan_task` attempts to use `execute_scan_task.delay(scan_id)` via **Celery**. If Celery is unavailable or fails, it gracefully (but dangerously) degrades to a daemonized `threading.Thread`.
- **Scan Orchestration**: The Celery worker runs `ScanOrchestrator.execute_scan(scan_id)`, which bridges the synchronous Celery environment into an asynchronous pipeline via `asyncio.run()`. The scan itself runs heavily parallelized async waves (`asyncio` tasks and thread pool executors for external tools).

## Concurrent Execution
- **Isolation**: Because execution happens in isolated Celery worker processes (and further isolated `subprocess.run` calls for CLI tools), parallel scans do not inherently share memory state.
- **Resource Contention**: The primary risk of concurrent scans is system-level resource exhaustion (CPU, Memory, File Descriptors) rather than state collisions, since tools like `nuclei` and `nmap` are heavy background processes.

## Error Handling & Logging
- **API Layer**: Standard Django REST Framework error handling is used (e.g., `serializer.is_valid(raise_exception=True)`).
- **Engine Layer**: `ScanOrchestrator` implements a broad `try...except Exception` block. It catches pipeline crashes, logs the full stack trace securely to the internal logger (`logger.error`), and updates the `Scan` model's status to `failed` with a sanitized `error_message`. Errors are not silently swallowed, and stack traces do not leak to the frontend.

## API Structure & Extensibility
- **Architecture**: The API is built using Django REST Framework class-based views.
- **Authentication**: Relies on `IsAuthenticated` and implicit tenant scoping via `request.user`.
- **Versioning**: There is **no explicit API versioning** (e.g., `/api/v1/`). All routes are mounted directly, which poses a risk for backward compatibility in a multi-tenant SaaS environment.
