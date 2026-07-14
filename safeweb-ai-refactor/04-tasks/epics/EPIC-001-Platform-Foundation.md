# EPIC-001: Platform Foundation & Scanning Safety

## Description
Secures the execution of the async engine by removing unsafe fallbacks and enforcing strict process limitations.

## Features & Tasks

### Feature 1: Strict Celery Enforcement (Phase 1)
- **Cites:** `01-architecture-spec.md §3.1 (REQ-ARCH-002)`, `11-monitoring-spec.md §3.1 (REQ-MON-002)`
- **Task 1.1:** Remove daemonized `threading.Thread` fallback in `_dispatch_scan_task`.
- **Task 1.2:** Return HTTP 503 if Celery broker is unreachable.
- **Task 1.3:** Implement liveness probes for the Celery worker queue.

### Feature 2: Subprocess Capping & Container Limits (Phase 2)
- **Cites:** `02-security-spec.md §3.2 (REQ-SEC-NFR-001)`, `03-scanner-engine-spec.md §3.1 (REQ-SCAN-002)`, `10-deployment-spec.md §3.1 (REQ-DEP-001)`
- **Task 2.1:** Implement `ulimit` and `timeout` wrappers around `subprocess.run` inside `ExternalTool` base class.
- **Task 2.2:** Establish max concurrency limits for CLI tools within `ScanOrchestrator`.
- **Task 2.3:** Containerize the worker environment with Docker to enforce memory caps (cgroups).
