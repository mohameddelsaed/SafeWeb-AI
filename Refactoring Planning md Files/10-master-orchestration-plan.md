# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 10: Master Orchestration Plan

**Status:** Phase 10 of 10 — final deliverable
**Populates:** `00-orchestration/master-orchestration-plan.md`
**Role of this document:** the single entry point. If you (or anyone on your team) only reads one file before starting, it's this one — it doesn't re-explain anything already specified in Deliverables 1–9, it just sequences and points to them.

---

## 1. What This Framework Is, In One Paragraph

This is not a refactor of `safeweb-ai`. It's the operating system that runs twelve specialist AI agents, in a fixed order with defined gates, to turn the current codebase into a complete, internally-consistent set of approved specifications and an implementation-ready task tree — at which point this framework's job is done and real development (by your 10-person team) begins. Nine deliverables (now ten) define every piece of that system; this one tells you which piece to use when.

---

## 2. The Complete Run Order

| Step | Phase | Who/What runs | Prompt source | Reads | Produces | Gate | Defined in |
|---|---|---|---|---|---|---|---|
| 1 | 0 | You (+ optional AI assist) | — (manual research) | Public docs, pricing pages | `01-research/*` | Gate 0 | Deliverable 7 §2 |
| 2 | 1 | Repository Analysis Agent | Deliverable 4 §2 | Full repo clone | `repo-map.md`, `integration-points.md`, `dead-or-orphaned-code.md` | Gate 1 | Deliverables 2 §1, 4 §2 |
| 3 | 2 | Architecture Analysis Agent | Deliverable 4 §3 | Step 2 outputs + research | `current-architecture-assessment.md`, `multi-tenancy-blockers.md` | Gate 2 | Deliverables 2 §2, 4 §3 |
| 4 | 2 | Security Review Agent | Deliverable 4 §4 | Step 2 outputs | `internal-security-review.md`, `tenant-isolation-risks.md` | Gate 2 | Deliverables 2 §3, 4 §4 |
| 5 | 2 | Scanner Engine Analysis Agent | Deliverable 4 §5 | Step 2 outputs + tool research | `scanner-accuracy-assessment.md`, `tool-fallback-gap-report.md`, `finding-normalization-review.md` | Gate 2 | Deliverables 2 §4, 4 §5 |
| 6 | 2 | AI Workflow Analysis Agent | Deliverable 4 §6 | Step 2 outputs + AI provider research | `current-ai-architecture.md`, `provider-coupling-report.md`, `prompt-inventory.md` | Gate 2 | Deliverables 2 §5, 4 §6 |
| 7 | 2 | Database Analysis Agent | Deliverable 4 §7 | Step 2 outputs + tenancy research | `current-schema-assessment.md`, `tenant-data-model-gap-report.md` | Gate 2 | Deliverables 2 §6, 4 §7 |
| 8 | 2 | Frontend Analysis Agent | Deliverable 4 §8 | Step 2 outputs | `frontend-assessment.md`, `non-expert-usability-gaps.md` | Gate 2 | Deliverables 2 §7, 4 §8 |
| 9 | 3 | Backend Analysis Agent | Deliverable 4 §9 | Step 2 + Step 3 (Architecture) | `backend-assessment.md`, `concurrency-and-scaling-gaps.md` | Gate 3 | Deliverables 2 §8, 4 §9 |
| 10 | 4 | SaaS Readiness Agent | Deliverable 4 §10 | Outputs of Steps 3, 4, 7, 9 | `saas-readiness-scorecard.md`, `cloud-deployment-blockers.md` | Gate 4 | Deliverables 2 §9, 4 §10 |
| 11 | 5 | Refactoring Planner Agent | Deliverable 4 §11 | ALL of Steps 2–10 | `refactoring-sequence.md`, `critical-path.md`, `risk-register.md` | **Gate 5 (major)** | Deliverables 2 §10, 4 §11, 7 §2 |
| 12 | 6 | Spec Generation Agent | Deliverable 4 §12 | Step 11 + all prior findings + `decisions.md` | All 12 draft specs | — | Deliverables 2 §11, 4 §12, 5 |
| 13 | 6 | QC Checker (utility pass) | Deliverable 9 §2 | All 12 draft specs | `qc-report-<date>.md` | — | Deliverable 9 §2 |
| 14 | 6 | You | — (manual review) | QC report, all 12 specs | Specs promoted to `Status: approved` (or sent back) | **Gate 6 (major)** | Deliverables 5, 9 |
| 15 | 7 | Implementation Planning Agent | Deliverable 4 §13 | Approved specs only | Full `04-tasks/` tree, `07-implementation-plans/` | Gate 7 | Deliverables 2 §12, 3, 4 §13 |
| — | ongoing | Real development begins | — | Implementation plans | Actual code in `safeweb-ai` | — | outside this framework's scope |

Steps 3–8 (Phase 2) can run in any order or in parallel — they only share a dependency on Step 2, not on each other.

---

## 3. Complete Framework File Map

Everything this framework produces, in one tree, cross-referenced to where it's defined:

```
safeweb-ai-refactor/
├── README.md                          # points here first
├── 00-orchestration/
│   ├── master-orchestration-plan.md   # this document
│   ├── execution-pipeline.md          # Deliverable 7
│   ├── agent-registry.md              # Deliverable 1 §2
│   ├── handoff-protocol.md            # Deliverable 8
│   ├── run-log.md                     # Deliverable 1 §2, used per Deliverable 7 §5
│   ├── decisions.md                   # seeded in §4 below
│   └── master-traceability-index.md   # Deliverable 8 §4
├── 01-research/                       # Deliverable 1 §3, owned by Phase 0
├── 02-agents/
│   ├── prompts/                       # Deliverable 4, all 12 + addendum from Deliverable 8 §2.3
│   ├── outputs/<NN-agent>/runs/run-N/ # Deliverable 8 §3 (amended structure)
│   └── context-packages/              # Deliverable 8 §1
├── 03-specs/                          # Deliverable 5, all 12 + _spec-template.md
├── 04-tasks/                          # Deliverable 3 scaffold, finalized by Step 15
├── 05-templates/                      # Deliverable 6, all 8 templates
├── 06-quality-control/
│   ├── validation-checklists/         # Deliverable 9 §1
│   ├── review-gates.md                # Deliverable 9 §3
│   ├── consistency-rules.md           # Deliverable 9 §4
│   └── qc-report-<date>.md            # generated at Step 13
└── 07-implementation-plans/           # finalized by Step 15
```

---

## 4. Seeding `decisions.md` — Don't Start Empty

Four decisions are already implied by the audit answers and shouldn't be re-litigated by any agent. Create `00-orchestration/decisions.md` with these as the first entries before Step 1 runs:

```markdown
# Decisions Log

## DEC-001: Deployment target is cloud (AWS or Azure), provider TBD
Date: <today>
Decided by: Omar
Rationale: explicit answer in project audit. Final AWS-vs-Azure choice deferred
to Deployment Spec (Step 12), informed by 01-research/deployment-research/.
Status: partially open — "cloud, not self-hosted" is final; specific provider is not.

## DEC-002: Multi-tenant architecture, from the foundation up
Date: <today>
Decided by: Omar
Rationale: explicit answer in project audit. Isolation pattern (shared-schema vs
schema-per-tenant vs DB-per-tenant) deferred to Multi-Tenancy Spec (Step 12),
informed by Database Analysis Agent (Step 7).
Status: "multi-tenant" is final; isolation pattern is not.

## DEC-003: External security tools are optional at runtime
Date: <today>
Decided by: Omar
Rationale: tools installed on the server when available, but the system must
remain correct via SafeWeb's own fallback scripts when absent. This is a hard
product requirement, not a nice-to-have — Scanner Engine Spec must not weaken
this to "best effort."
Status: final.

## DEC-004: AI provider strategy — free-tier-first, flexible, with local fallback
Date: <today>
Decided by: Omar
Rationale: OpenRouter (free tier) as default, with support for ChatGPT/Claude/
other paid providers as pluggable options, per-user-configurable choice, and
Ollama retained as a local fallback. This shapes AI Pipeline Spec directly.
Status: final on strategy; specific provider list may grow over time via the
plug-in pattern (AI Pipeline Spec FEAT-008).
```

---

## 5. Definition of Done for This Framework

The framework's job ends — and real implementation begins — when all of the following are true simultaneously:

1. All 12 specs in `03-specs/` are `Status: approved`.
2. `06-quality-control/qc-report-<date>.md` shows zero unresolved FAIL or NEEDS-HUMAN-JUDGMENT items.
3. `00-orchestration/master-traceability-index.md` shows every Critical/High finding with a non-empty Epic/Task column.
4. `04-tasks/` and `07-implementation-plans/` exist and every task cites an approved spec section.
5. You've personally read and signed off at Gate 5 and Gate 6 — the two gates this entire framework was built around protecting.

At that point, `07-implementation-plans/` is what your team actually works from. This framework's documents become reference material, not active output — though `decisions.md` and `master-traceability-index.md` stay live throughout implementation as the ledger of "why did we decide this" and "is this finding actually fixed yet."

---

## 6. Immediate Next Actions

In order:

1. Create the folder structure from §3 above (a single `mkdir -p` pass against the tree).
2. Write `decisions.md` using §4 above as the starting content.
3. Start Phase 0 — populate `01-research/`. This is the only phase with no AI agent driving it; budget real time for it, since Steps 5, 6, and 10 are only as good as this research is.
4. Run the Repository Analysis Agent (Deliverable 4 §2) against the real `safeweb-ai` repo. This is the first point where the framework touches actual code.
5. From there, follow the Run Order table (§2) top to bottom — each row tells you exactly what to read, what to run, and what gate to clear before moving to the next.

---

## 7. A Closing Note on Scope

This framework is intentionally heavier than a one-person side project needs — it's built for a 10-person team working against a real graduation deliverable, where contradictory specs or silently-dropped findings cost actual team coordination time, not just your own. That's also exactly why Gate 5 explicitly asks "is this sequence realistically executable by your team in your timeline" before any spec gets written — the framework can sequence findings correctly and still propose something your team can't actually build in the time available. That judgment call stays yours at every major gate; the framework's job is making sure you have everything you need to make it well, not making it for you.

---

**This completes all 10 deliverables of the AI execution framework for the SafeWeb AI refactor.**
