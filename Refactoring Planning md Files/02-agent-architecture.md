# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 2: AI Agent Architecture

**Status:** Phase 2 of 10
**Depends on:** `00-orchestration/`, `01-research/`, `02-agents/` folder structure from Deliverable 1

---

## 0. Architecture Pattern

This is a **pipeline of specialist agents with a thin orchestrator**, not a swarm of autonomous agents negotiating with each other. Each agent:

- Runs once per phase (re-runnable if inputs change)
- Reads a defined, bounded set of inputs — never "the whole repo, figure it out"
- Writes to exactly one folder in `02-agents/outputs/<NN>-<agent-name>/`
- Never writes specs or task breakdowns directly — analysis agents produce *findings*, only the Spec Generation and Refactoring Planner agents produce *prescriptions*. This separation is deliberate: it stops an agent from jumping to "fix this" before the full picture exists, which is the single biggest cause of contradictory specs.

**Global Context Pack** (every agent receives this, not repeated per-agent below):
- `00-orchestration/decisions.md` (ADR ledger — never contradict a logged decision; if a finding conflicts with one, flag it, don't silently override it)
- `01-research/tool-availability-matrix/` (so no agent assumes a tool is always present)
- Finding-ID and file-naming conventions from Deliverable 1 §8
- The product framing: AI-powered vuln scanner for non-security-specialist users, multi-tenant SaaS, cloud-deployed, free-tier-AI-first with paid/local fallback

---

## 1. Repository Analysis Agent
**Folder:** `02-agents/outputs/01-repository-analysis/`

- **Responsibilities:** Build the ground-truth map of what currently exists — no opinions, no recommendations. Inventory every module, service, script, and integration point. Identify language/framework versions, build tooling, entry points, and how components currently talk to each other (or don't).
- **Inputs:** Full repo clone, `dependency-manifest.md`, `commit-history-summary.md`
- **Outputs:** `repo-map.md` (component inventory with one-line purpose per component), `integration-points.md` (every place two components communicate, and how — REST call, shared DB, file system, message queue, none), `dead-or-orphaned-code.md`
- **Required context:** None beyond Global Context Pack — this agent is intentionally the most "blank slate" of all twelve, since its job is observation, not judgment.
- **Success criteria:** Every file in the repo is accounted for in `repo-map.md`; every cross-component call in the codebase has a matching entry in `integration-points.md`; zero recommendations or severity judgments appear anywhere in its output (those belong to later agents).
- **Handoff requirements:** `repo-map.md` and `integration-points.md` are required inputs for every other analysis agent (2–9). This agent must run first and complete before any other agent starts.

---

## 2. Architecture Analysis Agent
**Folder:** `02-agents/outputs/02-architecture-analysis/`

- **Responsibilities:** Evaluate the *shape* of the system against the target shape (multi-tenant, cloud-deployed SaaS). Identify monolith-vs-service boundaries, coupling/cohesion problems, single points of failure, and anything that structurally blocks multi-tenancy (e.g., global state, hardcoded single-user assumptions, shared mutable file paths).
- **Inputs:** `repo-map.md`, `integration-points.md`, `multi-tenancy-patterns.md`
- **Outputs:** `current-architecture-assessment.md` (using the template from `05-templates/architecture-assessment-template.md`), `multi-tenancy-blockers.md` (each blocker gets an `ARCH-NNN` ID with severity and which component owns it)
- **Required context:** Repository Analysis Agent output (must run after Agent 1)
- **Success criteria:** Every multi-tenancy blocker identified in Deliverable 9's QC pass is traceable to an `ARCH-NNN` entry here; no architectural claim lacks a citation to a specific file/component from `repo-map.md`.
- **Handoff requirements:** Feeds Refactoring Planner Agent (10) and SaaS Readiness Agent (9) directly; feeds Spec Generation Agent (11) for the Architecture Spec.

---

## 3. Security Review Agent
**Folder:** `02-agents/outputs/03-security-review/`

- **Responsibilities:** Review SafeWeb AI's *own* security posture (this product is a security scanner — its own vulnerabilities are existentially worse than average). Covers auth, tenant data isolation, secrets handling, API key storage (especially user-supplied AI provider keys), input handling around scan targets, and report/data exposure between tenants.
- **Inputs:** `repo-map.md`, `integration-points.md`, the auth/session-handling code paths specifically
- **Outputs:** `internal-security-review.md`, `tenant-isolation-risks.md`, each finding as `SEC-NNN` with severity
- **Required context:** Repository Analysis Agent output; must be aware this product stores other people's scan results and possibly their AI provider API keys — that data itself is high-value to an attacker.
- **Success criteria:** Every place a tenant's data (scan results, API keys, target URLs) is stored or transmitted has been reviewed for cross-tenant leakage; auth flow is fully traced end to end with no gaps.
- **Handoff requirements:** Feeds Security Spec and Multi-Tenancy Spec directly; any `SEC-NNN` marked Critical/High blocks the Refactoring Planner from sequencing other work ahead of it (review gate, defined in Deliverable 7).

---

## 4. Scanner Engine Analysis Agent
**Folder:** `02-agents/outputs/04-scanner-engine-analysis/`

- **Responsibilities:** Analyze the actual scanning logic — custom recon scripts plus external tool invocations (nuclei, httpx, subfinder, etc.). Assess accuracy/false-positive behavior, how results are normalized, and — directly tied to your answer on tool availability — verify and document exactly what happens when each external tool is missing: does the fallback script produce equivalent findings, degraded findings, or silently nothing.
- **Inputs:** `repo-map.md`, scanner module source, `required-vs-optional-tools.md`, `fallback-script-inventory.md`
- **Outputs:** `scanner-accuracy-assessment.md`, `tool-fallback-gap-report.md` (this is the critical one — any fallback that silently degrades without telling the user is flagged `SCAN-NNN` Critical), `finding-normalization-review.md`
- **Required context:** Repository Analysis Agent output; the existing tool-availability research from Deliverable 1
- **Success criteria:** Every external tool dependency has a documented, tested fallback behavior — "works without it" is verified against actual code, not assumed; false-positive-prone checks are explicitly listed.
- **Handoff requirements:** Feeds Scanner Engine Spec directly; `tool-fallback-gap-report.md` is required input for the Refactoring Planner since gaps here directly affect product trustworthiness.

---

## 5. AI Workflow Analysis Agent
**Folder:** `02-agents/outputs/05-ai-workflow-analysis/`

- **Responsibilities:** Analyze how AI is currently used for vulnerability analysis, reporting, and chatbot interaction. Map every prompt currently in use, every place a provider API is called, and how provider/model is currently selected (vs. the target: per-user-configurable, OpenRouter-first, paid-provider-ready, Ollama-fallback).
- **Inputs:** `repo-map.md`, AI/chatbot module source, `openrouter-capabilities.md`, `ollama-local-fallback.md`, `provider-abstraction-options.md`
- **Outputs:** `current-ai-architecture.md`, `provider-coupling-report.md` (everywhere the code assumes one specific provider/SDK — each is `AI-NNN`), `prompt-inventory.md`
- **Required context:** Repository Analysis Agent output; understanding that "AI choice flexible per user" is a hard product requirement, not a nice-to-have
- **Success criteria:** Every direct, hardcoded provider/SDK call is identified as a coupling point that the AI Pipeline Spec must abstract away; prompt inventory covers 100% of AI-driven features (vuln analysis, report generation, chatbot).
- **Handoff requirements:** Feeds AI Pipeline Spec directly; `provider-coupling-report.md` is required input for Refactoring Planner.

---

## 6. Database Analysis Agent
**Folder:** `02-agents/outputs/06-database-analysis/`

- **Responsibilities:** Assess current schema, data model, and — critically — whether and how tenant data is currently segregated (likely: not at all, if this started as a single-user tool). Evaluate migration history, indexing, and whether the schema can support shared-schema vs. schema-per-tenant vs. DB-per-tenant without a full rewrite.
- **Inputs:** `repo-map.md`, schema files/migrations, ORM models
- **Outputs:** `current-schema-assessment.md`, `tenant-data-model-gap-report.md` (`DB-NNN` per gap)
- **Required context:** Repository Analysis Agent output; `multi-tenancy-patterns.md`
- **Success criteria:** Every table is classified as tenant-scoped, global, or ambiguous; every ambiguous table is resolved before this agent's output is accepted (ambiguity here is a guaranteed source of cross-tenant leakage later).
- **Handoff requirements:** Feeds Database Spec and Multi-Tenancy Spec; required input for Security Review Agent's tenant-isolation findings (these two agents should be re-run together if one's findings shift).

---

## 7. Frontend Analysis Agent
**Folder:** `02-agents/outputs/07-frontend-analysis/`

- **Responsibilities:** Assess the UI/UX layer for a non-security-specialist audience — this product's whole value proposition is making scan results understandable to non-experts, so this agent evaluates whether the frontend actually does that (or just dumps raw tool output). Also assesses component structure, state management, and multi-tenant readiness of the UI (tenant switching, scoped views).
- **Inputs:** `repo-map.md`, frontend source, any existing UI screenshots/recordings
- **Outputs:** `frontend-assessment.md`, `non-expert-usability-gaps.md` (`FE-NNN`)
- **Required context:** Repository Analysis Agent output; product framing (non-specialist end users)
- **Success criteria:** Every screen that displays raw scan/tool output without explanation or severity context is flagged; component reusability and state management are assessed against multi-tenant requirements (no global singleton state that would leak between tenant sessions).
- **Handoff requirements:** Feeds Architecture Spec (frontend section) and Refactoring Planner.

---

## 8. Backend Analysis Agent
**Folder:** `02-agents/outputs/08-backend-analysis/`

- **Responsibilities:** Assess API layer, job/queue handling for scans (scans are long-running — how are they orchestrated today: sync, async, queued?), error handling, and logging. This is the agent that determines whether the backend can survive concurrent multi-tenant scan load or whether it was built assuming one scan at a time.
- **Inputs:** `repo-map.md`, `integration-points.md`, backend/API source
- **Outputs:** `backend-assessment.md`, `concurrency-and-scaling-gaps.md` (`BE-NNN`)
- **Required context:** Repository Analysis Agent output; Architecture Analysis Agent output (run after Agent 2)
- **Success criteria:** Scan execution model (sync/async/queue) is explicitly documented with evidence; every place that would break under concurrent multi-tenant load is flagged with severity.
- **Handoff requirements:** Feeds API Spec, Deployment Spec, and Refactoring Planner directly.

---

## 9. SaaS Readiness Agent
**Folder:** `02-agents/outputs/09-saas-readiness/`

- **Responsibilities:** Synthesize findings from Agents 2, 3, 6, 8 specifically against SaaS requirements: multi-tenancy, billing/usage-metering readiness (even if billing isn't built yet, is usage trackable per tenant?), onboarding flow, and cloud deployability on AWS or Azure. This agent does not generate new low-level findings — it aggregates and scores.
- **Inputs:** Outputs of Agents 2 (Architecture), 3 (Security), 6 (Database), 8 (Backend); `aws-vs-azure-comparison.md`
- **Outputs:** `saas-readiness-scorecard.md` (using `saas-readiness-review-template.md`), `cloud-deployment-blockers.md`
- **Required context:** Must run after Agents 2, 3, 6, 8 complete
- **Success criteria:** Every blocker on the scorecard traces back to a specific `ARCH-`, `SEC-`, `DB-`, or `BE-` finding ID — this agent is forbidden from introducing net-new findings without that traceability, since its job is synthesis, not discovery.
- **Handoff requirements:** Required input for Refactoring Planner Agent and Spec Generation Agent (SaaS Spec, Deployment Spec).

---

## 10. Refactoring Planner Agent
**Folder:** `02-agents/outputs/10-refactoring-plan/`

- **Responsibilities:** Take every finding from Agents 1–9 and sequence them into a coherent, dependency-aware refactoring order. Decides what must happen before what (e.g., tenant data model before tenant-scoped API endpoints before frontend tenant switching). Produces the skeleton that the Task Hierarchy (`04-tasks/`) gets built from.
- **Inputs:** All outputs from Agents 1–9
- **Outputs:** `refactoring-sequence.md` (phases, not yet task-level detail), `critical-path.md`, `risk-register.md` (using `risk-assessment-template.md`)
- **Required context:** This is the first agent that needs the *complete* analysis picture — it must not run until Agents 1–9 are all marked complete in `agent-registry.md`.
- **Success criteria:** Every Critical/High finding across all prior agents appears somewhere in the sequence with a phase assignment; no phase depends on something sequenced after it (circular dependency check).
- **Handoff requirements:** Feeds Spec Generation Agent (provides the priority order specs should be written in) and is the direct input to Deliverable 3's task breakdown.

---

## 11. Spec Generation Agent
**Folder:** `02-agents/outputs/11-specs-draft/`

- **Responsibilities:** Convert findings + refactoring sequence into the actual Spec-Kit documents (`03-specs/`). This is the first agent that produces *prescriptive*, forward-looking content rather than analysis of the current state.
- **Inputs:** All Agent 1–10 outputs; `_spec-template.md`; `00-orchestration/decisions.md`
- **Outputs:** Draft versions of all 12 specs listed in Deliverable 1 §5
- **Required context:** Refactoring Planner output (for sequencing/priority); every spec must explicitly resolve, not ignore, every open finding that falls in its domain
- **Success criteria:** Each spec passes the Deliverable 5 validation criteria before being marked "draft complete"; no spec contradicts another (cross-spec consistency check against `decisions.md`) — this is the primary target of Deliverable 9's "no contradictory requirements" check.
- **Handoff requirements:** Drafts go through the review gate in `06-quality-control/` before being marked approved; approved specs are the only valid input to Agent 12.

---

## 12. Implementation Planning Agent
**Folder:** `02-agents/outputs/12-implementation-plan/`

- **Responsibilities:** Convert approved specs into the execution-ready task tree (`04-tasks/`) and final implementation plans (`07-implementation-plans/`) that a coding agent (or you, or your team) can pick up and build from directly — concrete enough that no further interpretation is needed.
- **Inputs:** All approved specs from `03-specs/`, `refactoring-sequence.md`
- **Outputs:** Full Epic → Feature → Task → Subtask tree; phase-organized implementation plans
- **Required context:** Only approved specs — never draft specs. This agent must not run until Deliverable 9's QC gate has cleared the spec set.
- **Success criteria:** Every approved spec has at least one corresponding Epic; every task cites the spec section that justifies it; a task with no spec citation is rejected at the review gate.
- **Handoff requirements:** Terminal node — output here is what gets handed to actual implementation (human developers or coding agents working on the real `safeweb-ai` repo).

---

## Topology Summary

```
                 ┌─────────────────────────┐
                 │  1. Repository Analysis │   (must run first, alone)
                 └────────────┬────────────┘
                              │
        ┌──────────┬──────────┼──────────┬──────────┬──────────┐
        ▼          ▼          ▼          ▼          ▼          ▼
   2.Architecture 3.Security 4.Scanner 5.AI-Wkflw 6.Database 7.Frontend
        │          │          │          │          │          │
        └──────────┴──────────┴────┬─────┴──────────┴──────────┘
                                    ▼
                         8. Backend Analysis (needs Arch.)
                                    │
                                    ▼
                         9. SaaS Readiness (needs 2,3,6,8)
                                    │
                                    ▼
                       10. Refactoring Planner (needs ALL of 1–9)
                                    │
                                    ▼
                       11. Spec Generation  →  QC Gate (06-quality-control)
                                    │
                                    ▼
                     12. Implementation Planning  →  04-tasks/ + 07-implementation-plans/
```

Agents 2–7 can run in parallel since they only depend on Agent 1. Agent 8 waits on Agent 2 specifically (architecture shape determines what "backend concurrency" even means here). Agents 9 onward are strictly sequential — each genuinely needs the full prior picture, not a partial one.

---

*Next: Deliverable 3 — Master Task Breakdown (Epics → Features → Tasks → Subtasks, populating `04-tasks/`).*
