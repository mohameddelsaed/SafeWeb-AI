# SafeWeb AI Refactor — AI Execution Framework
## Deliverable 8: AI Handoff System

**Status:** Phase 8 of 10
**Populates:** `00-orchestration/handoff-protocol.md`
**Distinct from Deliverable 7:** the Execution Pipeline says *when* agents run and what gates them; this deliverable says *exactly how* information physically moves between them without loss or distortion.

---

## 0. Amendment Note (read this first)

Building this out in full surfaced two small gaps in earlier deliverables. Rather than silently working around them, they're logged here explicitly — which is exactly the behavior this framework demands of its own agents (Shared Preamble rule: flag gaps, don't paper over them).

1. **Deliverable 1's flat output folders** (`02-agents/outputs/<agent>/file.md`) don't account for re-runs. §3 below replaces that with a `runs/` subfolder structure. This is a refinement, not a contradiction — the agent-folder-per-domain structure stays exactly as designed.
2. **Deliverable 4's Shared Preamble** didn't instruct agents to generate their own handoff summary. §2 below adds this as a new closing step every agent prompt must include going forward. If you've already saved the Deliverable 4 prompts, append the snippet in §2.3 to each one's Shared Preamble copy.

---

## 1. Context Packaging — Full Specification

Every agent run produces a context package at `02-agents/context-packages/<NN>-<agent-name>-run<N>/` containing exactly four files:

```
02-agents/context-packages/03-security-review-run1/
├── manifest.md
├── inputs-used.md
├── summary-for-next-agent.md
└── traceability-id-map.md
```

### 1.1 `manifest.md`
```markdown
---
Agent: Security Review Agent
Run number: 1
Run date: <date>
Status: complete | failed | superseded
Superseded by: <run number, if applicable — otherwise "none">
---
One-paragraph plain summary of what this run accomplished and any notable
caveats (e.g., "auth flow trace complete; secrets inventory partial pending
access to the deployment config files, see Blocked section in full output").
```

### 1.2 `inputs-used.md`
The literal, exact list of files consulted — including which **run number** of any upstream agent's output was used. This pins provenance: if Architecture Analysis gets re-run and produces a run-2, every package created using run-1 stays correctly labeled as having used run-1, even after run-2 exists. Nothing is ever silently "whatever's newest" — it's always explicit.

### 1.3 `summary-for-next-agent.md`
Covered in full in §2 below — this is the most important file in the package and gets its own section.

### 1.4 `traceability-id-map.md`
Every finding ID minted by this specific run, in a flat list: `ID | Severity | One-line description`. This feeds the master traceability index (§4).

---

## 2. Summary Generation Rules

### 2.1 What gets compressed vs. preserved in full
- **Critical and High severity findings:** full description carried verbatim into the summary, not compressed. Losing nuance on a Critical finding because it got flattened into a one-liner is the single most expensive failure mode this system can have — a downstream agent (especially the Refactoring Planner, which works almost entirely from summaries) needs enough detail to sequence it correctly, not just know it exists.
- **Medium and Low severity findings:** one line each — `ID | Severity | One-sentence description` — is sufficient.
- **Narrative/assessment prose** (the "why" behind findings): compressed to a single sentence per finding pointing back at the full document, never reproduced at length in the summary.

### 2.2 Hard rules
- A summary is strictly a compression of true content — it may never add interpretation, speculation, or framing that wasn't in the source output.
- If a summary would exceed roughly 150 lines, that's a signal the upstream agent's output was too large or too unfocused, or that the downstream agent genuinely needs the full document rather than a digest — flag it in the manifest rather than silently truncating.
- Summaries are written by the source agent itself, as the final step of its own run, since it has full context of what it just produced and which findings actually matter most. This is a new closing instruction added to every agent prompt:

### 2.3 Addendum to Shared Preamble (Deliverable 4) — append this to every agent prompt
```
8. FINAL STEP — GENERATE YOUR HANDOFF SUMMARY. After producing your primary
   outputs, write summary-for-next-agent.md following these rules:
   - Critical/High findings: full description, verbatim, not shortened
   - Medium/Low findings: one line each (ID | Severity | one-sentence description)
   - Narrative sections: one sentence pointing back to the full document, never
     reproduced at length
   - You are compressing, not interpreting — add no new framing or speculation
   - If your honest summary would exceed ~150 lines, say so explicitly in
     manifest.md instead of writing an oversized summary
```

---

## 3. Knowledge Preservation

Nothing produced by an agent is ever deleted or silently overwritten — including outputs that later turn out to be wrong. Corrections are new entries, not edits-in-place, because erasing history is exactly what makes a framework un-auditable.

**Output structure (amends Deliverable 1):**
```
02-agents/outputs/03-security-review/
├── runs/
│   ├── run-1/
│   │   ├── internal-security-review.md
│   │   └── tenant-isolation-risks.md
│   └── run-2/
│       ├── internal-security-review.md
│       └── tenant-isolation-risks.md
└── CURRENT.md      # "run-2 is canonical as of <date>. run-1 superseded
                     #  because: auth flow trace was incomplete — see
                     #  00-orchestration/run-log.md entry 2026-XX-XX"
```

- `CURRENT.md` always states *why* a re-run happened, not just which run is newest — that reasoning is itself valuable to anyone reading the project history later.
- `00-orchestration/decisions.md` remains the single source of truth for anything already settled. No agent re-derives a decision already logged there; it cites it.
- Spec versions follow the same logic via their own `Change Log` section (Deliverable 5 §1) rather than a separate `runs/` folder, since specs are meant to evolve in place with full history visible inline.

---

## 4. Traceability Requirements

Every artifact in this framework must be traceable in both directions:

- **Backward:** a finding ID (`SEC-014`) traces to the exact agent, run number, and file/line in the actual repo that produced it.
- **Forward:** that same finding ID traces to the spec section that resolved it, the Epic/Feature/Task it became, and — once real implementation starts — the actual commit or PR (outside this framework's scope, but the ID should carry forward into commit messages so the chain doesn't break at the handoff to real development).

**`00-orchestration/master-traceability-index.md`** — a single running table, updated incrementally as agents run, so "is SEC-014 actually fixed yet" is answerable at a glance instead of requiring a manual search across twelve specs and a task tree:

```markdown
| Finding ID | Severity | Source (agent/run) | Addressed in spec | Epic/Task | Status |
|---|---|---|---|---|---|
| SEC-014 | Critical | 03-security-review/run-1 | 02-security-spec.md §3.2 | EPIC-004/TASK-015 | not-started |
```

This index is appended to, never rewritten — when an agent re-runs and supersedes a finding, the old row stays with a note, and a new row is added rather than the old one being edited away.

---

## 5. Artifact Naming Conventions (consolidated, authoritative)

| Artifact type | Convention | Example |
|---|---|---|
| Folders requiring order | Two-digit numeric prefix | `03-specs/`, `02-agents/outputs/04-scanner-engine-analysis/` |
| Finding IDs | `<DOMAIN>-<NNN>`, zero-padded to 3 digits, domain from fixed list | `ARCH-007`, `SEC-014` |
| Finding ID domain list | `ARCH, SEC, SCAN, AI, DB, FE, BE` only — Repository Analysis (Agent 1) and SaaS Readiness (Agent 9) never mint new IDs, by design (Deliverable 2/4) | — |
| Epic/Feature/Task/Subtask IDs | `EPIC-NNN`, `FEAT-NNN`, `TASK-NNN`, `SUBTASK-NNN` — flat global numbering, never per-epic-local | `TASK-014` |
| Spec files | Two-digit prefix matching Deliverable 5's fixed order | `07-multi-tenancy-spec.md` |
| Agent run folders | `run-N`, N starting at 1, never reused even after a run is superseded | `run-2` |
| Context package folders | `<NN>-<agent-name>-run<N>` | `03-security-review-run1` |
| File extension | `.md` for every artifact this framework produces internally | — |

IDs are assigned once, in discovery order, and never renumbered — even if a later-discovered finding turns out to be more severe than an earlier one. Renumbering would break every citation already written against the old ID, which is a worse outcome than a slightly non-intuitive ordering.

---

*Next: Deliverable 9 — Quality Control Framework (the concrete checks — no hallucinated findings, no missing components, no incomplete specs, no contradictions — that the gates referenced throughout this framework actually run.)*
