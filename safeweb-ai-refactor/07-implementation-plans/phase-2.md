# Implementation Plan: Phase 2 (Subprocess Scaling)

## Goal
Containerize and throttle external CLI tools to prevent system resource exhaustion under concurrent scan loads.

## Tasks
1. **Task 2.1: CLI Tool Process Limits**
   - Epic: EPIC-001-Platform-Foundation
   - Spec: 02-security-spec.md
   - Details: Apply `timeout` and maximum memory limit wrappers to all `subprocess.run` calls in `ExternalTool` base class.
2. **Task 2.2: Scan Concurrency Limits**
   - Epic: EPIC-001-Platform-Foundation
   - Spec: 03-scanner-engine-spec.md
   - Details: Limit maximum concurrent active tool scans via a Semaphore in `ScanOrchestrator`.
3. **Task 2.3: Containerized Workers**
   - Epic: EPIC-001-Platform-Foundation
   - Spec: 10-deployment-spec.md
   - Details: Write a `Dockerfile.worker` that isolates the Celery process and limits global host memory.

## Exit Criteria
- Firing 100 concurrent nuclei scans does not cause OOM on the host machine.
