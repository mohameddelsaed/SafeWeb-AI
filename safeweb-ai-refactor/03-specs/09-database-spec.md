---
Spec ID: 09-database-spec
Version: 1.0
Status: approved
Source agent: Spec Generation Agent
Run date: 2026-06-23
Supersedes: none
---

## 1. Purpose & Scope
Governs the target database schema, indexing strategy, and data migrations.

## 2. Findings Addressed
| Finding ID | Source Agent | How This Spec Resolves It |
|---|---|---|
| DB-001 | Database Agent | Standardizes the schema using a shared `Tenant` model. |

## 3. Requirements
### 3.1 Functional Requirements
- REQ-DB-001: All core models (`Scan`, `Vulnerability`) must contain a non-nullable `tenant_id` foreign key.
- REQ-DB-002: The schema must use PostgreSQL as the primary RDBMS.

### 3.2 Non-Functional Requirements
- REQ-DB-NFR-001: A composite index on `(tenant_id, id)` must be created for high-volume tables to ensure fast tenant-scoped lookups.

## 4. Out of Scope
- Application-level ORM filtering (see 07-multi-tenancy-spec).

## 5. Dependencies
- Depends on: 07-multi-tenancy-spec
- Depended on by: 01-architecture-spec

## 6. Open Questions / Decisions Needed
- None

## 7. Acceptance Criteria
Django migrations pass successfully, and queries missing `tenant_id` indexes are flagged.

## 8. Change Log
| Version | Date | What changed | Why |
|---|---|---|---|
| 1.0 | 2026-06-23 | Initial draft | Agent 11 execution |
