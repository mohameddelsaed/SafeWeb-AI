# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 3: Master Task Breakdown

**Status:** Phase 3 of 10
**Populates:** `04-tasks/`
**Depends on:** Deliverable 2 (agent topology), the audit answers (multi-tenant, cloud, tool-optional, flexible AI provider)

---

## 0. How To Read This Document

This is a **scaffold, not a final backlog**. The full, evidence-backed task tree only gets finalized by the Implementation Planning Agent (Agent 12) once Agents 1–11 have actually run against the real repository and produced approved specs — a task written today, before the Repository Analysis Agent has even looked at the code, can't yet cite real findings.

What this document *does* provide, and what makes it usable starting now:

1. The **complete Epic list** — every category of work required to take SafeWeb AI from its current state to a production multi-tenant SaaS. This list is fixed; agents will fill in Features/Tasks/Subtasks under it, but should not need to invent new Epics later. If they do, that's a signal the analysis phase found something this scaffold missed, and it gets added to `decisions.md` as a logged exception.
2. **Feature-level breakdown** for every Epic, derived directly from the audit answers and the agent responsibilities in Deliverable 2.
3. **Full Task → Subtask depth worked through for two Epics** (Tenant Foundation, AI Provider Abstraction) — the two structurally riskiest and most novel areas — to set the granularity standard every other Epic must match once Agent 12 expands it.
4. The **ID and dependency conventions** that make this tree usable as an actual project board (GitHub Projects, Jira, Linear — anything with parent/child issues and blocking relationships).

---

## 1. ID Conventions

- `EPIC-NNN`, `FEAT-NNN`, `TASK-NNN`, `SUBTASK-NNN` — flat numbering within each type, never reused.
- Every Feature cites the spec section that justifies it: `(spec: 07-multi-tenancy-spec.md §2)`.
- Every Task that depends on another carries `blocked-by: TASK-XXX`.
- Every Task born from a specific finding carries `source: ARCH-014` (or `SEC-`, `DB-`, etc.) — tasks with no spec citation and no finding citation are rejected at the QC review gate (Deliverable 9).
- Status values: `not-started`, `blocked`, `in-progress`, `in-review`, `done`.

---

## 2. Complete Epic List

| ID | Epic | Why it exists |
|---|---|---|
| EPIC-001 | Tenant Foundation & Isolation | Core multi-tenancy requirement — almost everything else depends on this existing first |
| EPIC-002 | AI Provider Abstraction Layer | OpenRouter-first, per-user configurable, paid-provider-ready, Ollama fallback |
| EPIC-003 | Scanner Engine Hardening & Tool-Fallback Reliability | Tools optional on the server; system must stay correct without them |
| EPIC-004 | Security Hardening of SafeWeb AI Itself | A vuln scanner that leaks tenant data or API keys is an existential failure |
| EPIC-005 | Backend Concurrency & Job Orchestration | Multi-tenant means concurrent scans; current system likely assumes one-at-a-time |
| EPIC-006 | Cloud Deployment & Infrastructure | AWS/Azure target, containerization, CI/CD |
| EPIC-007 | Frontend Multi-Tenant UX & Non-Expert Usability | Tenant-scoped UI + the core product promise of explaining results to non-specialists |
| EPIC-008 | Reporting Engine Overhaul | Tenant-scoped, explainable, exportable reports |
| EPIC-009 | Chatbot / AI Interaction Layer | Provider-agnostic conversational interface over scan results |
| EPIC-010 | Observability & Monitoring | Logging, metrics, tenant-scoped audit trails |
| EPIC-011 | SaaS Platform Enablement | Onboarding, usage metering, plan/tier scaffolding (billing-ready, not necessarily billing-live) |
| EPIC-012 | Spec-Kit & Orchestration Bootstrapping | Running Agents 1–12 themselves, populating `03-specs/` and `04-tasks/` for real |

EPIC-012 is chronologically first — nothing else can be sequenced with confidence until it's done. It's listed last here because it's about *this framework*, not the product itself.

---

## 3. Feature-Level Breakdown Per Epic

### EPIC-001 — Tenant Foundation & Isolation
- FEAT-001 Tenant data model & schema strategy *(spec: 09-database-spec.md)*
- FEAT-002 Tenant-aware auth & session scoping *(spec: 07-multi-tenancy-spec.md)*
- FEAT-003 Tenant context propagation through the request lifecycle *(spec: 01-architecture-spec.md)*
- FEAT-004 Cross-tenant leakage test suite *(spec: 02-security-spec.md)*

### EPIC-002 — AI Provider Abstraction Layer
- FEAT-005 Provider-agnostic AI gateway interface *(spec: 04-ai-pipeline-spec.md)*
- FEAT-006 OpenRouter integration as default free-tier path
- FEAT-007 Per-user provider/model selection settings
- FEAT-008 Paid-provider plug-in support (designed, not necessarily all wired up)
- FEAT-009 Ollama local fallback path

### EPIC-003 — Scanner Engine Hardening & Tool-Fallback Reliability
- FEAT-010 Tool-availability detection at scan runtime
- FEAT-011 Fallback script parity audit & gap closure *(source: SCAN-NNN findings)*
- FEAT-012 User-facing degraded-mode disclosure ("this scan ran without nuclei — coverage reduced")
- FEAT-013 Finding normalization across tool-present vs. fallback paths

### EPIC-004 — Security Hardening of SafeWeb AI Itself
- FEAT-014 API key / secrets storage hardening (especially user-supplied AI provider keys)
- FEAT-015 Auth flow hardening *(source: SEC-NNN findings)*
- FEAT-016 Tenant data isolation enforcement at the data-access layer
- FEAT-017 Input handling hardening around user-submitted scan targets

### EPIC-005 — Backend Concurrency & Job Orchestration
- FEAT-018 Async scan job queue (replacing sync execution if found)
- FEAT-019 Per-tenant scan concurrency limits & fair scheduling
- FEAT-020 Job failure handling & retry semantics

### EPIC-006 — Cloud Deployment & Infrastructure
- FEAT-021 AWS vs Azure final decision *(logged to decisions.md)*
- FEAT-022 Containerization of all services
- FEAT-023 Infrastructure-as-code for chosen cloud
- FEAT-024 CI/CD pipeline

### EPIC-007 — Frontend Multi-Tenant UX & Non-Expert Usability
- FEAT-025 Tenant switching / scoped views
- FEAT-026 Non-expert result explainability layer *(source: FE-NNN findings)*
- FEAT-027 Elimination of global/singleton state that could leak across tenant sessions

### EPIC-008 — Reporting Engine Overhaul
- FEAT-028 Tenant-scoped report generation
- FEAT-029 Export formats (PDF/HTML at minimum, given the docx/pdf skill ecosystem you already use elsewhere)
- FEAT-030 Severity-explained, non-jargon report templates

### EPIC-009 — Chatbot / AI Interaction Layer
- FEAT-031 Chatbot wired through the provider-agnostic AI gateway (depends on EPIC-002)
- FEAT-032 Scan-result-grounded conversation context (no hallucinated findings in chat)

### EPIC-010 — Observability & Monitoring
- FEAT-033 Centralized, tenant-tagged logging
- FEAT-034 Scan job metrics & dashboards
- FEAT-035 Audit trail for tenant data access

### EPIC-011 — SaaS Platform Enablement
- FEAT-036 Onboarding flow (tenant signup → first scan)
- FEAT-037 Usage metering (scans/month, AI calls/month per tenant)
- FEAT-038 Plan/tier scaffolding (even if only one free tier launches initially)

### EPIC-012 — Spec-Kit & Orchestration Bootstrapping
- FEAT-039 Run Agents 1–9 against the real repo
- FEAT-040 Run Refactoring Planner & Spec Generation Agents
- FEAT-041 QC review gate pass on all specs
- FEAT-042 Run Implementation Planning Agent to finalize this task tree

---

## 4. Worked Example A — EPIC-001: Tenant Foundation & Isolation

### FEAT-001: Tenant data model & schema strategy
- **TASK-001** Decide tenant isolation pattern (shared-schema-with-tenant-id vs. schema-per-tenant) *(blocked-by: research in `multi-tenancy-patterns.md`)*
  - SUBTASK-001 Document tradeoffs against current schema size/complexity
  - SUBTASK-002 Log final decision in `decisions.md` with rationale
- **TASK-002** Add tenant identifier to every tenant-scoped table *(blocked-by: TASK-001)*
  - SUBTASK-003 Identify every table classified "tenant-scoped" or "ambiguous" in `tenant-data-model-gap-report.md`
  - SUBTASK-004 Write migration scripts per table
  - SUBTASK-005 Add NOT NULL + foreign-key constraints tying tenant_id to the tenants table
- **TASK-003** Resolve every table flagged "ambiguous" by the Database Analysis Agent *(source: DB-NNN, blocked-by: TASK-001)*

### FEAT-002: Tenant-aware auth & session scoping
- **TASK-004** Audit current auth flow end-to-end *(source: SEC-NNN)*
- **TASK-005** Embed tenant context in session/token claims
  - SUBTASK-006 Update token issuance to include tenant_id
  - SUBTASK-007 Update every auth middleware check to validate tenant_id against the requested resource
- **TASK-006** Add tenant-switch flow for users belonging to multiple tenants (if product requires this — confirm against Product Spec)

### FEAT-003: Tenant context propagation through the request lifecycle
- **TASK-007** Define how tenant context flows from request → service layer → data layer (middleware injection vs. explicit parameter passing — decision logged to `decisions.md`)
- **TASK-008** Apply chosen pattern across all backend services *(blocked-by: TASK-007, depends on EPIC-005 sequencing)*

### FEAT-004: Cross-tenant leakage test suite
- **TASK-009** Write automated tests: tenant A can never read/write tenant B's data, across every API endpoint
  - SUBTASK-008 Generate endpoint inventory from `integration-points.md`
  - SUBTASK-009 Write one negative-access test per endpoint
- **TASK-010** Add this suite as a required CI gate *(blocked-by: EPIC-006 FEAT-024 CI/CD pipeline existing)*

---

## 5. Worked Example B — EPIC-002: AI Provider Abstraction Layer

### FEAT-005: Provider-agnostic AI gateway interface
- **TASK-011** Define a single internal interface every AI feature (vuln analysis, reporting, chatbot) calls through — no feature talks to a provider SDK directly *(source: AI-NNN provider-coupling findings)*
  - SUBTASK-010 Specify the interface contract (request/response shape, streaming support, error semantics)
  - SUBTASK-011 Refactor every direct provider call found in `provider-coupling-report.md` to go through the gateway

### FEAT-006: OpenRouter integration as default free-tier path
- **TASK-012** Implement OpenRouter as the default gateway backend
- **TASK-013** Map OpenRouter's free-tier model list to internal model identifiers, with graceful handling when a free model is rate-limited or deprecated

### FEAT-007: Per-user provider/model selection settings
- **TASK-014** Add a tenant/user-level settings record for AI provider + model choice *(blocked-by: TASK-002, since this is itself a tenant-scoped table)*
- **TASK-015** Settings UI for provider/model selection *(depends on EPIC-007)*
- **TASK-016** Validate selected provider/model against what's actually configured/available before allowing save (no silent failures at scan time)

### FEAT-008: Paid-provider plug-in support
- **TASK-017** Design plug-in pattern so adding a new paid provider (Anthropic, OpenAI direct, etc.) means writing one adapter against the FEAT-005 interface, not touching feature code
- **TASK-018** Implement one paid-provider adapter as the reference implementation, proving the pattern

### FEAT-009: Ollama local fallback path
- **TASK-019** Define fallback trigger conditions (no API key configured, all configured providers unreachable, explicit user choice)
- **TASK-020** Implement Ollama adapter against the FEAT-005 interface
- **TASK-021** Document hardware/model expectations for self-hosted deployments using this fallback (ties to `ollama-local-fallback.md`)

---

## 6. Cross-Cutting Tasks (apply across multiple Epics, tracked once each)

- **TASK-022** Establish a shared testing strategy doc — unit/integration/e2e split, and specifically how cross-tenant tests (FEAT-004) and AI-provider-switch tests (EPIC-002) get covered
- **TASK-023** Establish a migration/rollback strategy for schema changes given this is a live, evolving student-built repo with no production users yet (lower risk now than it will be post-launch — worth stating explicitly in `decisions.md` so later agents don't over-engineer rollback safety prematurely)
- **TASK-024** Establish a documentation-as-you-go rule: every Epic's "done" definition includes its corresponding spec section being updated to match what was actually built, not just what was planned

---

*Next: Deliverable 4 — Prompt Library (the full, production-grade prompt text for each of the 12 agents defined in Deliverable 2).*
