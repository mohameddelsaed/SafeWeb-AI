# Implementation Plan: Phase 1 (Foundation & Safety)

## Goal
Eliminate the dangerous in-memory threading fallback and secure the Celery background task execution model before concurrent load increases.

## Tasks
1. **Task 1.1: Remove Threading Fallback**
   - Epic: EPIC-001-Platform-Foundation
   - Spec: 01-architecture-spec.md
   - Details: Remove `threading.Thread` fallback from `apps/scanning/views.py`.
2. **Task 1.2: Enforce Celery Queuing**
   - Epic: EPIC-001-Platform-Foundation
   - Spec: 01-architecture-spec.md
   - Details: Throw a 503 Service Unavailable if `execute_scan_task.delay()` fails to connect to the Redis broker.
3. **Task 1.3: Liveness Probes**
   - Epic: EPIC-001-Platform-Foundation
   - Spec: 11-monitoring-spec.md
   - Details: Expose a `/health/celery` endpoint to ensure workers are alive.

## Exit Criteria
- Disconnecting Redis successfully fails a scan creation with HTTP 503 rather than silently hanging a background thread in the web API process.
