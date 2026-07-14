---
Spec ID: 01-architecture-spec
Version: 1.0
Status: approved
Source agent: Spec Generation Agent
Run date: 2026-06-23
Supersedes: none
---

## 1. Purpose & Scope
Governs the high-level system architecture, service boundaries, and core data flow. It does NOT govern the database schema (see 09-database-spec).

## 2. Findings Addressed
| Finding ID | Source Agent | How This Spec Resolves It |
|---|---|---|
| BE-002 | Backend Agent | Eliminates in-memory threading fallback; enforces Celery as the sole task queue (REQ-ARCH-002). |

## 3. Requirements
### 3.1 Functional Requirements
- REQ-ARCH-001: The system shall use Django for the API and React for the frontend SPA.
- REQ-ARCH-002: All async scanning tasks must be executed via Celery with Redis as the broker. Fallbacks to in-memory threading are strictly prohibited.

### 3.2 Non-Functional Requirements
- REQ-ARCH-NFR-001: The architecture must support stateless API nodes for horizontal scaling.

## 4. Out of Scope
- Exact schema design.
- Deployment infrastructure details.

## 5. Dependencies
- Depends on: 00-product-spec
- Depended on by: 08-api-spec, 09-database-spec

## 6. Open Questions / Decisions Needed
- None

## 7. Acceptance Criteria
System runs exclusively on Celery for background tasks, and all components defined in repo-map are correctly retained or removed.

## 8. Change Log
| Version | Date | What changed | Why |
|---|---|---|---|
| 1.0 | 2026-06-23 | Initial draft | Agent 11 execution |
