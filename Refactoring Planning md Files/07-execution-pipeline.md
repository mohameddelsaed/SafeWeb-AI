# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 7: Execution Pipeline

**Status:** Phase 7 of 10
**Populates:** `00-orchestration/execution-pipeline.md`
**Formalizes:** the topology sketched in Deliverable 2, the agent registry/run-log placeholders from Deliverable 1.

---

## 0. One Gap This Deliverable Has To Close First

None of the previous six deliverables actually assign an owner to populating `01-research/` (tool-availability matrix, AI provider research, deployment research, competitor landscape). Several agents — notably 2, 4, 5, 9 — read from it as required context. That folder can't stay empty when Agent 1 fires. So this pipeline adds a **Phase 0** that didn't exist as a numbered phase before: research-pack assembly, owned by you (and optionally AI-assisted, but not one of the 12 specialist agents — it's reconnaissance, not analysis of the codebase).

---

## 1. Pipeline Overview

| Phase | Agents | Execution mode | Depends on | Gate after |
|---|---|---|---|---|
| 0 | Research Pack Assembly | Human-led (AI-assisted optional) | — | Gate 0: Research completeness |
| 1 | 01 Repository Analysis | Solo | Phase 0 | Gate 1: Inventory completeness |
| 2 | 02 Architecture, 03 Security, 04 Scanner, 05 AI Workflow, 06 Database, 07 Frontend | Parallel | Phase 1 | Gate 2: Per-agent output validation |
| 3 | 08 Backend Analysis | Solo | Agent 02 specifically (from Phase 2) | Gate 3: Architecture-dependency check |
| 4 | 09 SaaS Readiness | Solo (synthesis only) | Agents 02, 03, 06, 08 | Gate 4: No-new-findings check |
| 5 | 10 Refactoring Planner | Solo | ALL of Agents 1–9 | **Gate 5 — Major Review Gate (human)** |
| 6 | 11 Spec Generation | Solo (writes 12 specs) | Phase 5 approved | **Gate 6 — QC Gate (Deliverable 9 rules)** |
| 7 | 12 Implementation Planning | Solo | Approved specs only | Gate 7: Final pre-handoff sanity check |
| — | Periodic re-runs (Tech Debt, Scalability templates) | As needed, post-launch | Phase 7 complete | No formal gate — informational |

Phases 2's six agents have no dependency on each other and can genuinely run in any order or simultaneously — they only need Phase 1's output. Everything from Phase 3 onward is strictly sequential because each phase genuinely needs the *complete* prior picture, not a partial one.

---

## 2. Phase Detail

### Phase 0 — Research Pack Assembly
**Owner:** You (Omar) — this is reconnaissance work outside the codebase, not something an agent should hallucinate about. AI can assist (e.g., asking a model to summarize OpenRouter's published rate limits), but every claim here needs a real source, since Agents 2, 4, 5, and 9 will treat this folder as ground truth.
**Deliverables:** Everything listed under `01-research/` in Deliverable 1 §3.
**Gate 0 criteria:** Each research file exists, is non-empty, and cites real sources (docs, pricing pages, official repos) rather than assumption. Missing files block the affected downstream agents specifically — Agent 1 can still proceed without this being finished, since it doesn't depend on it.

### Phase 1 — Repository Analysis
**Gate 1 criteria:** Spot-check `repo-map.md` against an actual file count of the repo (e.g., `find . -type f | wc -l` compared to entries listed) — if the agent's inventory is missing a meaningful fraction of files, re-run with a more explicit instruction to walk every directory, don't sample. Confirm zero opinion-language slipped into the output (per Deliverable 4's constraint).

### Phase 2 — Parallel Analysis Wave
**Gate 2 criteria (applied per-agent, not as one combined gate):** Each of the six outputs has a valid header block, every finding has a properly formatted ID and citation, and no agent's output strayed outside its defined scope (anything that did belongs in that agent's "Out-of-Scope Observations" section, not woven into its main findings). Agents in this wave can be re-run independently of each other — a problem with the Security Review output doesn't require re-running Frontend.

### Phase 3 — Backend Analysis
**Gate 3 criteria:** Confirm Agent 02's `current-architecture-assessment.md` is genuinely complete (not just present) before starting — Backend Analysis explicitly needs architecture's read on service boundaries to assess concurrency meaningfully, so a thin or rushed architecture output will silently produce a weak backend assessment.

### Phase 4 — SaaS Readiness
**Gate 4 criteria:** This is the constraint check that matters most for this specific agent (per Deliverable 2 §9 and Deliverable 4 §10): every line in its scorecard must cite an existing finding ID from Agents 2/3/6/8. If review finds even one scorecard entry without a citation, send it back — this agent inventing findings undermines the entire "synthesis only" design.

### Phase 5 — Refactoring Planner — Major Review Gate
This is the first point where a human (you) should read the output in full before letting the pipeline continue, not just spot-check it. Two things make this gate higher-stakes than 1–4: it's the last point before the framework starts being prescriptive (Spec Generation), and it's where project-management judgment — team size, timeline, what's realistic for a graduation project — has to be applied, which the agent has no visibility into beyond what's in `decisions.md`.
**Gate 5 criteria:**
- Findings Coverage Check passes (no Critical/High finding left unplaced)
- The phase sequencing actually matches your team's real capacity — if `refactoring-sequence.md` proposes a sequence that's not realistically executable by a 10-person student team in your remaining timeline, this is the place to push back, before specs get written against a plan you can't actually follow
- Critical path makes sense given the audit answers (multi-tenancy and AI provider abstraction should plausibly anchor it — if they don't, ask why)

### Phase 6 — Spec Generation — QC Gate
The heaviest gate in the pipeline; full rules are Deliverable 9. Summarized here:
- Every spec passes its individual validation criteria from Deliverable 5
- Cross-spec consistency rules (Deliverable 5 §3) hold across all 12 specs simultaneously
- No spec is promoted to `Status: approved` until both checks pass
**Expect at least one revision round.** Twelve interdependent specs written in one pass rarely come out fully consistent on the first try — budget for the Spec Generation Agent being re-run against specific reviewer feedback (e.g., "Database Spec and Multi-Tenancy Spec disagree on the isolation pattern, resolve and regenerate both") rather than expecting zero-iteration success.

### Phase 7 — Implementation Planning — Final Sanity Check
**Gate 7 criteria:** Every Epic in the resulting `04-tasks/` tree traces to an approved spec; spot-check that the Tenant Foundation and AI Provider Abstraction epics (worked through to subtask level in Deliverable 3) still hold up against what the real, approved specs actually say — correct drift if the scaffold and the real specs diverge.

---

## 3. Context Transfer Strategy

The risk this section exists to manage: by Phase 5, the Refactoring Planner needs *all nine* prior agents' output. Feeding it nine full raw documents is both wasteful and risks burying the findings that matter under prose. The fix is the `context-packages/` structure from Deliverable 1 §4, used as follows:

After every agent run, before the next agent starts, produce three files in `02-agents/context-packages/<NN>-<agent-name>-run<N>/`:

1. **`inputs-used.md`** — exact list of files actually fed to the agent (not just "everything available" — the literal set).
2. **`summary-for-next-agent.md`** — a condensed digest: every finding ID with its one-line description and severity, stripped of supporting prose. This is what downstream agents that need *breadth* (like the Refactoring Planner) actually consume. Full narrative documents stay available for agents that need *depth* on one specific area (e.g., Spec Generation re-reading the full Security Review when writing the Security Spec, not just the digest).
3. **`traceability-id-map.md`** — running ledger of every finding ID issued by this agent, so ID collisions across agents are impossible to miss.

**Rule of thumb for which agents get full documents vs. digests:** an agent consuming output from one or two prior agents (e.g., Backend Analysis reading Architecture Analysis) gets the full document — the depth is worth it and the volume is manageable. An agent consuming output from many prior agents at once (Refactoring Planner reading all nine, Spec Generation Agent reading all ten) gets digests by default, with the ability to pull a specific full document when a finding needs more context than its one-line summary provides.

---

## 4. Review Gates Summary

| Gate | After | Reviewer | Stop-the-line condition |
|---|---|---|---|
| 0 | Research Pack Assembly | You | Any research file missing or unsourced |
| 1 | Repository Analysis | You (quick) or automated file-count check | Inventory clearly incomplete |
| 2 | Each Phase 2 agent | You (quick) or automated header/citation check | Malformed output, scope violation |
| 3 | Backend Analysis | You (quick) | Architecture output was incomplete when this ran |
| 4 | SaaS Readiness | You (quick) | Uncited scorecard entries |
| 5 | Refactoring Planner | **You (full read)** | Findings coverage gap, unrealistic sequencing |
| 6 | Spec Generation | **You (full read) + QC checklist** | Any cross-spec contradiction, any spec failing its own validation criteria |
| 7 | Implementation Planning | You (quick) | Uncited tasks, scaffold drift |

Gates 1–4 are designed to be fast — a few minutes each — precisely so Gates 5 and 6 can get your full attention. Don't let gate fatigue cause Gate 6 (the one most likely to catch a real, costly contradiction before any code gets written) to get rushed.

---

## 5. Failure & Retry Protocol

1. **First failure at any gate:** re-run the specific agent with corrective instructions appended (cite exactly what's wrong, point back at the relevant constraint from its prompt). Don't re-run the whole pipeline.
2. **Second consecutive failure on the same agent/gate:** stop and diagnose manually — at this point the problem is more likely an unclear prompt or insufficient input context than something the agent will fix on a third blind attempt. Check whether the agent's required inputs (per Deliverable 2) were actually complete and correctly packaged.
3. **A downstream agent's failure traces back to an upstream agent's gap:** fix upstream, then re-run everything downstream of that fix — don't patch the symptom at the downstream agent.
4. **Every retry gets logged in `00-orchestration/run-log.md`:** agent, attempt number, what failed, what changed before the re-run. This log is what makes Deliverable 9's quality-control framework auditable rather than just aspirational.

---

*Next: Deliverable 8 — AI Handoff System (formal context-packaging rules, summary-generation standards, knowledge preservation, and artifact naming conventions — expanding what §3 above introduced into a complete standalone system).*
