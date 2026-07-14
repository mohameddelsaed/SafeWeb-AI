# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 9: Quality Control Framework

**Status:** Phase 9 of 10
**Populates:** `06-quality-control/validation-checklists/`, `06-quality-control/review-gates.md`, `06-quality-control/consistency-rules.md`
**Relationship to Deliverable 7:** that deliverable said *when* gates happen; this deliverable defines *what actually gets checked* at each one — the concrete mechanics behind "Gate 5 criteria" and "Gate 6 criteria."

---

## 0. A Practical Constraint This Framework Has To Respect

You are not a QA department — you're one person reviewing the output of a twelve-agent pipeline, on a graduation-project timeline. A QC system that requires exhaustively re-verifying everything by hand will simply not get used. So this framework is built around a deliberate split: **mechanical checks get automated or semi-automated wherever possible**, freeing your actual judgment for the small number of checks that genuinely require it (real contradictions, realism of scope, architectural coherence). Gates 1–4 in Deliverable 7 stay fast specifically so your attention is fully available at Gates 5 and 6, where it matters most.

---

## 1. The Five Failure Modes

### 1.1 No Hallucinated Findings

**What this looks like concretely:** a finding ID that doesn't correspond to anything actually in the code, or a citation pointing to a file/line that, when reopened, doesn't actually support the claim made about it.

**Detection:**
- *Mechanical (checkable without re-reading the code):* every row in every findings table has a non-empty citation field. Any row without one is an automatic fail — this alone catches a large share of fabrication, since an agent that's hallucinating tends to either omit citations or reuse the same citation across unrelated findings.
- *Sampling-based (requires reopening the cited code):* you cannot verify 100% of findings by hand at this team size, so apply tiered sampling — **100% of Critical and High severity findings get manually verified** against their cited file:line before a spec built on them is approved; **a random 20% sample of Medium/Low findings** gets spot-checked per agent run. If the sample turns up a fabrication, the sample size for that agent's findings doubles before approval.

**Checklist (`06-quality-control/validation-checklists/hallucination-check.md`):**
```
[ ] Every finding row has a non-empty citation
[ ] No two unrelated findings share an identical citation
[ ] 100% of Critical/High findings verified against actual file:line
[ ] 20% random sample of Medium/Low findings verified
[ ] Any verification failure logged and sample size doubled for that agent
```
**Enforced at:** Gate 2 (per-agent, lightweight pass) and Gate 5/6 (full verification before specs are written against the findings).

---

### 1.2 No Missing Components

**What this looks like concretely:** something genuinely in the repo that no agent ever analyzed, so no finding could exist for it even if it has real problems — or, on the planning side, a spec requirement that never became an Epic/Task, so it would simply never get built despite being "approved."

**Detection:**
- *Repo-side coverage check:* cross-reference every component listed in `repo-map.md` (Agent 1) against the union of components mentioned across Agents 2–9's outputs. Anything in `repo-map.md` that's never referenced anywhere downstream is flagged "orphaned coverage" — it needs an explicit decision logged (either "out of scope for this refactor, here's why" in `decisions.md`, or sent back for analysis), not silent omission.
- *Spec-to-task coverage check:* cross-reference every spec's Functional Requirements (Deliverable 5 §1, section 3.1) against `00-orchestration/master-traceability-index.md` (Deliverable 8 §4). Any requirement ID with zero Epic/Task rows pointing to it is a planning-side missing-component gap.

**Checklist:**
```
[ ] Every component in repo-map.md is referenced by at least one Agent 2-9 output,
    OR has an explicit out-of-scope decision logged in decisions.md
[ ] Every numbered requirement (REQ-<SPEC>-NNN) across all 12 specs has at least
    one Epic/Task row in master-traceability-index.md
```
**Enforced at:** Gate 5 (repo-side check, since this is the last point before specs get written) and Gate 7 (spec-to-task check, the natural place since the task tree now exists).

---

### 1.3 No Incomplete Specifications

**What this looks like concretely:** a spec missing one of its required sections (Deliverable 5), a "Findings Addressed" table that doesn't actually cover every in-domain finding, or a spec promoted to `Status: approved` while its "Open Questions" section is still non-empty.

**Detection:** this is the most purely mechanical of the five checks — it's a structural diff against the template, not a judgment call.

**Checklist:**
```
[ ] All 8 shared-template sections present (Deliverable 5 §1)
[ ] All spec-specific required sections present (per Deliverable 5 §2 for that spec)
[ ] Every finding ID whose domain matches this spec appears in its Findings
    Addressed table (cross-check against master-traceability-index.md)
[ ] "Open Questions / Decisions Needed" section is empty before Status: approved
    is allowed — a non-empty Open Questions section is a hard block, not a warning
[ ] Every Functional/Non-Functional Requirement has a unique REQ-<SPEC>-NNN ID
```
**Enforced at:** Gate 6 — this check runs against all 12 specs before any of them can be marked approved.

---

### 1.4 No Contradictory Requirements

**What this looks like concretely:** two specs (or two requirements inside one spec) that cannot both be implemented as written — e.g., the Database Spec choosing schema-per-tenant isolation while the API Spec's middleware design assumes shared-schema row-level filtering.

**Detection:** the hardest of the five to automate, but made tractable by structure already built into the framework:
- *Decisions-ledger check (mechanical):* any spec content that contradicts an entry already logged in `decisions.md` is an automatic, easily-detected contradiction — this is a straightforward fact comparison, not a judgment call.
- *Dependency-graph check (semi-structured):* every spec's "Dependencies" section (Deliverable 5 §1, section 5) states what it depends on and what depends on it. Build this into an explicit graph after all 12 drafts exist, then for every `depends on` edge, confirm the downstream spec's usage of the upstream decision matches what the upstream spec actually says — not a reinterpretation of it. This narrows your manual reading from "read all 144 possible spec pairs" down to "read only the edges that actually exist."

**Checklist:**
```
[ ] Zero spec contents contradict a decisions.md entry
[ ] Dependency graph built from all 12 specs' Dependencies sections
[ ] For every dependency edge, downstream spec's usage matches upstream spec's
    actual stated decision (not a reinterpretation)
[ ] Any genuine contradiction found gets resolved by updating the upstream spec
    (the source of truth) and regenerating affected downstream specs — never
    patched by silently picking a side in just the downstream spec
```
**Enforced at:** Gate 6.

---

### 1.5 No Architectural Inconsistencies

**What this looks like concretely:** the same logical system described with a different shape in different documents — Architecture Spec assigns a responsibility to one service, API Spec groups its endpoints under a different one, Deployment Spec containerizes something that doesn't match either.

**Detection:** cross-check the component/service name list across exactly three documents that should describe the same system from three angles: Architecture Spec's component map, API Spec's endpoint-to-service grouping, and Deployment Spec's containerization unit list. These three lists of "what are the deployable/addressable components of this system" must match 1:1 — same names, same boundaries.

**Checklist:**
```
[ ] Component/service names in Architecture Spec, API Spec, and Deployment Spec
    are identical sets (not just similar)
[ ] Every component in one of these three documents appears in the other two,
    or its absence is explicitly justified (e.g., a shared library isn't a
    deployable unit, so it correctly appears only in Architecture Spec)
[ ] Multi-Tenancy Spec's isolation pattern decision is reflected consistently
    in Database Spec's schema design and API Spec's middleware design
```
**Enforced at:** Gate 6.

---

## 2. QC Checker — Lightweight Utility Pass

Given the volume of mechanical checks above, it's worth running them as a dedicated lightweight pass before your own Gate 6 review — not as one of the 12 substantive pipeline agents from Deliverable 2 (it analyzes nothing new and makes no judgment calls), but as a utility prompt that works through every checklist in this deliverable mechanically and hands you a pass/fail report, so your manual reading time goes entirely toward the things in §1.4 and §1.5 that genuinely need judgment.

```
[SHARED PREAMBLE — but this run produces no findings, only checklist results]

YOUR ROLE: QC Checker (utility pass, not a pipeline analysis agent)

TASK: Work through every checklist in 06-quality-control/validation-checklists/
against the actual current state of 03-specs/ and master-traceability-index.md.
For each checklist item: PASS, FAIL, or NEEDS-HUMAN-JUDGMENT (use this third
status for anything in the contradiction/consistency checks that requires
comparing intent, not just matching strings/IDs).

OUTPUT: 06-quality-control/qc-report-<date>.md — one row per checklist item
across all five failure-mode checklists, with PASS/FAIL/NEEDS-HUMAN-JUDGMENT and
a one-line reason. Anything FAIL or NEEDS-HUMAN-JUDGMENT gets a clear pointer to
exactly which spec/section to look at.

CONSTRAINT: You do not resolve anything yourself. You report status only — even
an obvious-looking contradiction gets reported, not silently fixed, since
deciding which side of a contradiction to keep is the kind of call this
framework reserves for human review at Gate 6.
```

---

## 3. Review Gates — Mechanics

This expands Deliverable 7 §4 with the actual pass/fail logic per gate, rather than just naming the gate.

| Gate | Failure modes checked | Mechanism |
|---|---|---|
| Gate 2 (per Phase-2 agent) | 1.1 (lightweight) | Citation-presence check only — full verification deferred to Gate 5 |
| Gate 4 (SaaS Readiness) | 1.1 (specific to this agent's no-new-findings rule) | Every scorecard line cites an existing finding ID |
| Gate 5 (Refactoring Planner) | 1.1 (full), 1.2 (repo-side) | Tiered sampling per §1.1; repo-map coverage check per §1.2 |
| Gate 6 (Spec Generation — the heaviest gate) | 1.3, 1.4, 1.5 (all of them) | Run QC Checker (§2) first, then human review focused on every NEEDS-HUMAN-JUDGMENT item |
| Gate 7 (Implementation Planning) | 1.2 (spec-side) | Every requirement traced to a task |

---

## 4. Consistency Rules (`06-quality-control/consistency-rules.md`)

The authoritative, standalone rule list — referenced by name from Deliverable 5 §3, formalized here:

```
1. No spec may reference an external tool without first checking
   01-research/tool-availability-matrix/ for its actual availability status.
2. No spec may assign a service/component responsibility that conflicts with
   Architecture Spec's component map (Architecture Spec is upstream of API
   and Deployment specs on this question).
3. Multi-Tenancy Spec is upstream of Database, API, and Security specs on any
   tenancy-related decision — divergence means Multi-Tenancy Spec needs
   updating, not the downstream spec quietly choosing its own answer.
4. Deployment Spec's cloud provider choice must match decisions.md exactly —
   it does not get to re-decide AWS vs. Azure independently.
5. AI Pipeline Spec may not introduce a provider absent from
   01-research/ai-provider-research/.
6. No requirement in any spec may go unaddressed by the task tree — every
   REQ-<SPEC>-NNN must appear in master-traceability-index.md with a
   downstream Epic/Task.
7. No spec may be marked Status: approved while its Open Questions section is
   non-empty.
8. Any contradiction discovered between two specs is resolved by correcting
   the upstream spec (per the Dependencies graph) and regenerating affected
   downstream specs — never by silently patching just the downstream one.
```

---

*Next: Deliverable 10 — Master Orchestration Plan (the final document tying all nine prior deliverables together into one operational playbook: which agent runs first, with which prompt, producing which document, through which gate, all the way to implementation-ready specs).*
