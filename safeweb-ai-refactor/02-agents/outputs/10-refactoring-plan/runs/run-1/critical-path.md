---
Source agent: Refactoring Planner Agent
Run date: 2026-06-23
Status: draft
---

# Critical Path

The critical path for the SafeWeb AI refactor is:

1. **Phase 1: Foundation & Safety** (Resolving BE-002: In-Memory Fallback Threading)
2. **Phase 2: Subprocess Scaling** (Resolving BE-003: Subprocess Resource Exhaustion)

Delaying Phase 1 blocks Phase 2, because ensuring that the Celery task queue is the sole execution mechanism is required before we can accurately measure and throttle subprocess concurrency limits.
