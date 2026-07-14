---
Report type: Risk Assessment
Source agent: Refactoring Planner Agent
Run date: 2026-06-23
Inputs used: 02-agents/outputs/01-repository-analysis/ through 09-saas-readiness/
Status: draft
---

## 1. Risk Register
| Risk ID | Description | Likelihood | Impact | Severity (L×I) | Phase affected | Mitigation | Owner |
|---|---|---|---|---|---|---|---|
| RISK-01 | Removing threading fallback (BE-002) causes scan failures if Celery misconfigures. | Medium | High | High | Phase 1 | Implement robust Celery liveness checks on API startup. | Platform Team |
| RISK-02 | Containerizing/limiting `nuclei` causes timeouts for valid complex scans. | Medium | Medium | Medium | Phase 2 | Benchmark and adjust process limits incrementally. | SecOps Team |

## 2. Top Risks — Narrative
The highest severity risk involves removing the in-memory threading fallback. While the fallback is unsafe under load, it currently masks Celery connectivity issues. Stripping it out means that if the Redis broker drops, scans will fail entirely rather than degrading gracefully. This requires a robust monitoring and liveness check mechanism.

## 3. Accepted Risks
- Schema migration risk is currently Low because there is no live production data yet — this risk level will need re-assessment once real tenants exist. We accept the lack of a sophisticated migration pattern at this exact moment.
