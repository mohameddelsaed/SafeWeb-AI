# EPIC-003: Multi-Tenancy Core

## Description
Establishes the database and API foundation for true tenant data isolation and usage tracking.

## Features & Tasks

### Feature 1: Shared Schema Tenant Isolation (Phase 4)
- **Cites:** `07-multi-tenancy-spec.md §3.1 (REQ-MT-001)`, `09-database-spec.md §3.1 (REQ-DB-001)`
- **Task 1.1:** Implement Django models with `tenant_id` foreign keys.
- **Task 1.2:** Write middleware to extract `tenant_id` from JWT tokens and enforce ORM isolation.
- **Task 1.3:** Create composite indexes for `(tenant_id, id)` on heavy tables.

### Feature 2: SaaS Usage Metering (Phase 4)
- **Cites:** `06-saas-spec.md §3.1 (REQ-SAAS-002)`
- **Task 2.1:** Implement scan usage counters per tenant.
- **Task 2.2:** Enforce rate limits based on the assigned tier (Free/Pro).
