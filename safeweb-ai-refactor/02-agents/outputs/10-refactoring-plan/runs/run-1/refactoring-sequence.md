---
Report type: Refactoring Plan
Source agent: Refactoring Planner Agent
Run date: 2026-06-23
Inputs used: 02-agents/outputs/01-repository-analysis/ through 09-saas-readiness/
Status: draft
---

## 1. Phase Overview
| Phase | Name | Goal | Depends on |
|---|---|---|---|
| Phase 1 | Foundation & Safety | Eliminate threading fallbacks and secure Celery execution. | None |
| Phase 2 | Subprocess Scaling | Containerize/limit external CLI tools to prevent resource exhaustion. | Phase 1 |
| Phase 3 | API Modernization | Implement formal API versioning. | Phase 1 |

## 2. Phase Detail
### Phase 1: Foundation & Safety
- Findings resolved: BE-002
- Deliverables: Celery fallback removed; robust task dispatching.
- Exit criteria: Scans only execute via Celery; failed dispatches return 503 instead of falling back to thread.

### Phase 2: Subprocess Scaling
- Findings resolved: BE-003
- Deliverables: Process limits and timeouts strictly enforced for CLI tools.
- Exit criteria: 100 concurrent scans do not exceed system RAM/CPU thresholds.

### Phase 3: API Modernization
- Findings resolved: BE-001
- Deliverables: `/api/v1/` prefix on all routes.
- Exit criteria: All endpoints successfully migrated and documented.

## 3. Critical Path
Phase 1 → Phase 2. Securing the async execution foundation (BE-002) is a prerequisite for safely scaling the subprocess execution (BE-003).

## 4. Sequencing Rationale
We must stabilize the baseline concurrency model before addressing resource exhaustion from individual tools. Versioning the API is lower priority but critical before SaaS onboarding.

## 5. Findings Coverage Check
| Finding ID | Severity | Phase assigned | Notes |
|---|---|---|---|
| BE-002 | High | Phase 1 | |
| BE-003 | High | Phase 2 | |
| BE-001 | Medium | Phase 3 | |
