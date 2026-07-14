# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 1: AI Project Structure

**Status:** Phase 1 of 10
**Scope:** This is the meta-project that orchestrates AI agents to analyze, specify, and plan the refactor of `safeweb-ai`. It is *not* the application repository itself — it lives alongside it and produces the artifacts (specs, task trees, plans) that downstream coding agents will later execute against the real codebase.

**Inputs baked into this design:**
- Deployment target: cloud (AWS or Azure) — undecided between the two, so structure stays provider-agnostic until the Deployment Spec phase
- Multi-tenant SaaS from day one
- Security tools (nuclei, httpx, subfinder, etc.) are installed on the server when available, but the system must degrade gracefully and remain correct without them, using SafeWeb's own scripts as fallback
- AI layer: free-tier OpenRouter as the default provider (covering GPT/Claude/etc. through one gateway), per-user configurable provider choice, paid providers supported as a future option, Ollama retained as a local fallback
- Execution mode: phase by phase, in order, with review between phases

---

## 1. Top-Level Folder Hierarchy

```
safeweb-ai-refactor/
├── 00-orchestration/              # The control plane — how agents run, in what order, with what context
├── 01-research/                   # Raw inputs agents need before they can reason about anything
├── 02-agents/                     # Agent prompt definitions + their raw outputs
├── 03-specs/                      # The Spec-Kit — target-state specifications (the "what to build")
├── 04-tasks/                      # Epic → Feature → Task → Subtask breakdown (the "how to build it")
├── 05-templates/                  # Reusable documentation templates referenced by agents
├── 06-quality-control/            # Validation rules, review gates, consistency checks
├── 07-implementation-plans/       # Final, execution-ready plans handed to coding agents
└── README.md                      # Entry point: explains the framework, points to 00-orchestration first
```

Rationale: numeric prefixes enforce reading/execution order in any file browser or IDE, independent of any tool's sort behavior. An agent (or you) should never have to guess what comes before what.

---

## 2. Orchestration Hierarchy (`00-orchestration/`)

```
00-orchestration/
├── master-orchestration-plan.md   # Deliverable 10 — lives here once written
├── execution-pipeline.md          # Deliverable 7 — agent run order, dependencies, gates
├── agent-registry.md              # Index of every agent: id, purpose, status, current owner (human/agent)
├── handoff-protocol.md            # Deliverable 8 — how context moves between agents
├── run-log.md                     # Append-only log: which agent ran when, against what inputs, what it produced
└── decisions.md                   # Architecture Decision Records (ADRs) — every irreversible choice, dated
```

`decisions.md` matters more than it looks: things like "AWS vs Azure," "which ORM," "tenant isolation strategy" will get decided once and then referenced by every later spec. Without a single ledger, agents will silently re-litigate or contradict earlier decisions — this is one of the main sources of the "contradictory requirements" failure mode Deliverable 9 has to guard against.

---

## 3. Research Hierarchy (`01-research/`)

```
01-research/
├── repository-snapshot/
│   ├── repo-tree.txt              # Full file tree at time of analysis (regenerated each major phase)
│   ├── dependency-manifest.md     # All package.json / requirements.txt / go.mod contents, consolidated
│   └── commit-history-summary.md  # High-signal history: major refactors, abandoned features, recurring bug areas
├── tool-availability-matrix/
│   ├── required-vs-optional-tools.md   # nuclei, httpx, subfinder, ffuf, etc. — which are hard deps vs degrade-gracefully
│   └── fallback-script-inventory.md    # Your own scripts that replace each tool when absent, and what accuracy/coverage is lost
├── ai-provider-research/
│   ├── openrouter-capabilities.md      # Free-tier model list, rate limits, routing behavior
│   ├── provider-abstraction-options.md # How to keep "AI choice per user" swappable without vendor lock-in
│   └── ollama-local-fallback.md        # Hardware requirements, which models are viable as offline fallback
├── deployment-research/
│   ├── aws-vs-azure-comparison.md      # Multi-tenant SaaS lens: managed Postgres, container orchestration, cost at student/early-stage scale
│   └── multi-tenancy-patterns.md       # Shared-schema vs schema-per-tenant vs DB-per-tenant tradeoffs
└── competitor-landscape.md             # What Burp Suite Enterprise, Acunetix, Pentest-Tools.com etc. do, for positioning only — not for copying
```

This folder exists so that every later agent cites *something concrete* instead of asserting from general knowledge. The Repository Analysis Agent (Deliverable 2) writes into `repository-snapshot/`; the SaaS Readiness Agent reads `deployment-research/` and `competitor-landscape.md` before forming an opinion.

---

## 4. Agent Hierarchy (`02-agents/`)

```
02-agents/
├── prompts/
│   ├── 01-repository-analysis-agent.md
│   ├── 02-architecture-analysis-agent.md
│   ├── 03-security-review-agent.md
│   ├── 04-scanner-engine-analysis-agent.md
│   ├── 05-ai-workflow-analysis-agent.md
│   ├── 06-database-analysis-agent.md
│   ├── 07-frontend-analysis-agent.md
│   ├── 08-backend-analysis-agent.md
│   ├── 09-saas-readiness-agent.md
│   ├── 10-refactoring-planner-agent.md
│   ├── 11-spec-generation-agent.md
│   └── 12-implementation-planning-agent.md
├── outputs/
│   ├── 01-repository-analysis/
│   ├── 02-architecture-analysis/
│   ├── 03-security-review/
│   ├── 04-scanner-engine-analysis/
│   ├── 05-ai-workflow-analysis/
│   ├── 06-database-analysis/
│   ├── 07-frontend-analysis/
│   ├── 08-backend-analysis/
│   ├── 09-saas-readiness/
│   ├── 10-refactoring-plan/
│   ├── 11-specs-draft/
│   └── 12-implementation-plan/
└── context-packages/
    └── (one folder per agent run, e.g. 03-security-review-run1/)
        ├── inputs-used.md          # Exact files/sections fed to the agent
        ├── summary-for-next-agent.md
        └── traceability-id-map.md  # Maps each finding to a stable ID (e.g. SEC-014) for cross-referencing later
```

Each agent's folder number matches its prompt number — a finding referenced as `outputs/03-security-review/SEC-014` is unambiguous everywhere downstream. This numbering is the backbone of Deliverable 8 (handoff system).

---

## 5. Spec Hierarchy (`03-specs/`) — the Spec-Kit

```
03-specs/
├── 00-product-spec.md
├── 01-architecture-spec.md
├── 02-security-spec.md
├── 03-scanner-engine-spec.md
├── 04-ai-pipeline-spec.md
├── 05-reporting-engine-spec.md
├── 06-saas-spec.md
├── 07-multi-tenancy-spec.md
├── 08-api-spec.md
├── 09-database-spec.md
├── 10-deployment-spec.md
├── 11-monitoring-spec.md
└── _spec-template.md              # Shared skeleton all of the above must follow (defined in Deliverable 5)
```

Specs are numbered by *dependency order*, not alphabetically: product spec first because everything else derives from it, multi-tenancy spec before API/database specs because tenant isolation strategy constrains both. Deployment and monitoring are last because they consume the rest.

---

## 6. Task Hierarchy (`04-tasks/`)

```
04-tasks/
├── epics/
│   └── EPIC-001-multi-tenant-foundation.md  (etc.)
├── features/
│   └── EPIC-001/
│       └── FEAT-001-tenant-isolation-layer.md
├── tasks/
│   └── EPIC-001/FEAT-001/
│       └── TASK-001-design-tenant-id-propagation.md
└── subtasks/
    └── EPIC-001/FEAT-001/TASK-001/
        └── SUBTASK-001-...md
```

Mirrors the spec numbering so a task can cite `(see 07-multi-tenancy-spec.md §3.2)` and a human can trace any subtask back to the product decision that justified it. Full breakdown is Deliverable 3.

---

## 7. Templates, QC, and Implementation Plans

```
05-templates/
├── repo-audit-report-template.md
├── architecture-assessment-template.md
├── security-review-template.md
├── refactoring-plan-template.md
├── risk-assessment-template.md
├── tech-debt-report-template.md
├── scalability-review-template.md
└── saas-readiness-review-template.md

06-quality-control/
├── validation-checklists/
│   └── (one per agent — defined in Deliverable 9)
├── review-gates.md
└── consistency-rules.md           # e.g. "no spec may reference a tool without checking tool-availability-matrix"

07-implementation-plans/
├── phase-1-foundation/
├── phase-2-multi-tenancy/
├── phase-3-ai-provider-abstraction/
└── phase-N-.../
```

---

## 8. Naming & Traceability Conventions (used everywhere above)

- **Finding IDs:** `<DOMAIN>-<NNN>` — `SEC-014`, `ARCH-007`, `DB-003`. Assigned once, never reused, never renumbered.
- **File prefixes:** two-digit numeric prefix = execution/reading order within a folder.
- **Every artifact** opens with a small header block: `Source agent`, `Run date`, `Inputs used`, `Status (draft/reviewed/approved)`. This is what makes Deliverable 9's "no hallucinated findings" check enforceable — anything without a traceable source agent and input list gets rejected at the review gate.

---

*Next: Deliverable 2 — AI Agent Architecture (full responsibilities/inputs/outputs/success criteria for each of the 12 agents listed above).*
