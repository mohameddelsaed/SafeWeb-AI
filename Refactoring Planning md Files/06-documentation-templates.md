# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 6: Documentation Templates

**Status:** Phase 6 of 10
**Populates:** `05-templates/`
**Used by:** Agents 1, 2, 3, 9, 10 directly (referenced by name in their Deliverable 4 prompts); also available for ad hoc re-audits after the initial pipeline run completes.

Each template below follows the same header-block convention as the spec template from Deliverable 5, so every produced document — spec or report — is identifiable and traceable the same way regardless of type.

---

## 1. Repository Audit Report Template
`05-templates/repo-audit-report-template.md`

**Used by:** Repository Analysis Agent (1), and any later re-audit once the codebase has moved on from the initial pipeline run.

```markdown
---
Report type: Repository Audit
Source agent: <agent name>
Run date: <date>
Inputs used: <list>
Status: draft
---

## 1. Audit Scope
What was included in this audit, and what was explicitly excluded (e.g., "third-
party vendored dependencies not reviewed line-by-line, only inventoried").

## 2. Component Inventory
| Path | Purpose (inferred) | Language/Framework | Entry point? |
|---|---|---|---|

## 3. Integration Points
| Source component | Target component | Mechanism | Citation (file:line) |
|---|---|---|---|

## 4. Dead or Orphaned Code
| Path | Confidence (high/med/low) | Evidence |
|---|---|---|

## 5. Notable Observations
Anything noticed that doesn't fit the tables above but seems relevant for later
agents (kept factual, no recommendations).

## 6. Audit Limitations
What wasn't reachable, reviewed, or could not be confirmed, and why.
```

---

## 2. Architecture Assessment Template
`05-templates/architecture-assessment-template.md`

**Used by:** Architecture Analysis Agent (2).

```markdown
---
Report type: Architecture Assessment
Source agent: <agent name>
Run date: <date>
Inputs used: <list>
Status: draft
---

## 1. Assessment Questions
Answer each explicitly, with citations:
1. Global/shared mutable state that risks cross-tenant leakage?
2. Service/module boundary cohesion — clean or tangled?
3. Single points of failure?
4. Single-user assumptions baked into the design?

## 2. Findings
| ID (ARCH-NNN) | Severity | Component | Description | Citation |
|---|---|---|---|---|

## 3. Current Component Map
Structured text representation of current components and how they connect
(can reference integration-points.md rather than duplicating it).

## 4. Multi-Tenancy Blocker Summary
Subset of findings above that specifically block multi-tenancy — this section's
content becomes multi-tenancy-blockers.md verbatim.

## 5. Out-of-Scope Observations
Anything noticed outside this agent's assessment questions (per Shared Preamble
rule 3) — flagged for the relevant downstream agent, not acted on here.
```

---

## 3. Security Review Template
`05-templates/security-review-template.md`

**Used by:** Security Review Agent (3).

```markdown
---
Report type: Security Review
Source agent: <agent name>
Run date: <date>
Inputs used: <list>
Status: draft
---

## 1. Scope & Methodology
What was reviewed (static code review of auth/secrets/data-handling paths) and
what was explicitly NOT performed (e.g., no dynamic/runtime penetration testing
was conducted as part of this review — this is a code-level analysis only).

## 2. Authentication & Session Flow Trace
Step-by-step trace from credential submission through session issuance and
verification, noting every gap found.

## 3. Secrets Handling Inventory
| Secret type | Storage method | Encrypted at rest? | Ever logged/exposed? | Citation |
|---|---|---|---|---|

## 4. Tenant Data Exposure Risks
Every storage/transmission point for tenant-owned data (scan results, target
URLs, reports), assessed for current or future cross-tenant exposure risk.

## 5. Input Handling Review
Scan-target and configuration input paths, reviewed for injection risk into the
scanning pipeline.

## 6. Findings
| ID (SEC-NNN) | Severity | Component | Description | Citation |
|---|---|---|---|---|

## 7. Out-of-Scope Observations
```

---

## 4. Refactoring Plan Template
`05-templates/refactoring-plan-template.md`

**Used by:** Refactoring Planner Agent (10) for `refactoring-sequence.md`.

```markdown
---
Report type: Refactoring Plan
Source agent: <agent name>
Run date: <date>
Inputs used: <list — should be ALL Agent 1-9 outputs>
Status: draft
---

## 1. Phase Overview
| Phase | Name | Goal | Depends on |
|---|---|---|---|

## 2. Phase Detail
For each phase:
### Phase N: <name>
- Findings resolved: <list of finding IDs>
- Deliverables: <what exists at the end of this phase>
- Exit criteria: <how to know this phase is genuinely done>

## 3. Critical Path
The shortest sequence of phases that, if delayed, delays everything downstream.

## 4. Sequencing Rationale
Why this order and not another — especially any non-obvious ordering decisions.

## 5. Findings Coverage Check
| Finding ID | Severity | Phase assigned | Notes |
|---|---|---|---|
Every Critical/High finding from Agents 1-9 MUST appear here with a phase. Any
that can't be placed gets explained, not silently dropped.
```

---

## 5. Risk Assessment Template
`05-templates/risk-assessment-template.md`

**Used by:** Refactoring Planner Agent (10) for `risk-register.md`.

```markdown
---
Report type: Risk Assessment
Source agent: <agent name>
Run date: <date>
Inputs used: <list>
Status: draft
---

## 1. Risk Register
| Risk ID | Description | Likelihood | Impact | Severity (L×I) | Phase affected | Mitigation | Owner |
|---|---|---|---|---|---|---|---|

## 2. Top Risks — Narrative
Plain-language explanation of the 3-5 highest-severity risks: what could go
wrong, what it would actually mean for the project if it did.

## 3. Accepted Risks
Risks deliberately not mitigated right now, with rationale. Example pattern:
"schema migration risk is currently Low because there is no live production
data yet — this risk level will need re-assessment once real tenants exist."
```

---

## 6. Technical Debt Report Template
`05-templates/tech-debt-report-template.md`

**Used by:** Not tied to a single pipeline agent — this one is for periodic re-use. Run it again after EPIC-012 completes and the team is mid-implementation, to track debt that accumulates during the build itself (the initial pipeline's findings already cover pre-existing debt; this template is for catching new debt as it's introduced).

```markdown
---
Report type: Technical Debt Report
Source agent / author: <agent or human name>
Run date: <date>
Inputs used: <list>
Status: draft
Previous report: <link, if this is a re-run — otherwise "none, first report">
---

## 1. Debt Inventory
| Item | Location | Origin/Cause | Cost of delay if unaddressed | Suggested priority |
|---|---|---|---|---|

## 2. Debt by Category
- Architectural debt:
- Code-level debt:
- Test-coverage debt:
- Documentation debt:
- Dependency/version debt:

## 3. Trend Notes
If this is a re-run: what's been resolved since the last report, what's new,
is the overall trend improving or worsening.
```

---

## 7. Scalability Review Template
`05-templates/scalability-review-template.md`

**Used by:** Backend Analysis Agent (8) and SaaS Readiness Agent (9) jointly inform this; also reusable post-launch as actual usage data becomes available (replacing assumptions with real numbers).

```markdown
---
Report type: Scalability Review
Source agent / author: <agent or human name>
Run date: <date>
Inputs used: <list>
Status: draft
---

## 1. Load Assumptions
| Dimension | Current (assumed/observed) | Target |
|---|---|---|
| Concurrent tenants | | |
| Concurrent scans | | |
| AI calls / minute | | |

Mark clearly whether each number is an actual measurement or an assumption —
before launch, most of this will necessarily be assumption, and that should be
stated plainly rather than presented as measured fact.

## 2. Bottleneck Inventory
| Component | Bottleneck type | Evidence | Severity |
|---|---|---|---|

## 3. Scaling Strategy Fit
Does the current/target architecture support horizontal scaling, and where
specifically (which components scale out cleanly, which don't and why).

## 4. Cost-at-Scale Notes
Rough cost trajectory as load grows, tied to the Deployment Spec's cloud choice.
```

---

## 8. SaaS Readiness Review Template
`05-templates/saas-readiness-review-template.md`

**Used by:** SaaS Readiness Agent (9).

```markdown
---
Report type: SaaS Readiness Review
Source agent: <agent name>
Run date: <date>
Inputs used: <list — Agents 2, 3, 6, 8 outputs plus deployment research>
Status: draft
---

## 1. Readiness Scorecard
| Dimension | Score (Not Started / Partial / Ready) | Justifying Findings | Notes |
|---|---|---|---|
| Multi-tenancy completeness | | | |
| Tenant data isolation | | | |
| Concurrent-load readiness | | | |
| Cloud deployability | | | |
| Onboarding readiness | | | |
| Usage trackability | | | |

Every row's "Justifying Findings" column must cite real finding IDs — per this
agent's strict no-new-findings constraint (Deliverable 2 §9).

## 2. Blocker List
Ranked list of everything currently preventing a cloud multi-tenant launch,
each citing its source finding(s).

## 3. Launch Readiness Statement
Plain-language summary: ready / partially ready / not ready for a multi-tenant
cloud demo or soft launch, and the single biggest reason why.
```

---

*Next: Deliverable 7 — Execution Pipeline (the full agent run sequence with dependencies, context-transfer strategy, review gates, and validation checkpoints, formalizing what's been referenced throughout the framework so far).*
