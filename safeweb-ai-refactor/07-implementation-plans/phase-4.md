# Implementation Plan: Phase 4 (Multi-Tenancy & AI Reporting)

## Goal
Implement the data isolation logic and the AI reporting pipeline for tenants.

## Tasks
1. **Task 1.1: Tenant ID Foreign Keys**
   - Epic: EPIC-003-Multi-Tenancy-Core
   - Spec: 09-database-spec.md
   - Details: Run migrations adding `tenant_id` to core models.
2. **Task 1.2: Tenant ORM Middleware**
   - Epic: EPIC-003-Multi-Tenancy-Core
   - Spec: 07-multi-tenancy-spec.md
   - Details: Filter querysets implicitly based on the `request.user.tenant_id`.
3. **Task 2.1: AI Provider Abstraction**
   - Epic: EPIC-004-AI-Reporting
   - Spec: 04-ai-pipeline-spec.md
   - Details: Move hardcoded prompts to a registry and build an LLM abstraction layer.
4. **Task 2.2: PDF Reporting**
   - Epic: EPIC-004-AI-Reporting
   - Spec: 05-reporting-engine-spec.md
   - Details: Generate PDF reports from AI-summarized vulnerability findings.

## Exit Criteria
- Two distinct tenants cannot view each other's scans.
- Scan findings can be successfully summarized by the AI engine and exported to a PDF.
