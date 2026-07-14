# SafeWeb AI — Master Execution Prompt
## The prompt you send with all 10 framework files to start the real work

---

## CONTEXT FOR OMAR BEFORE SENDING

**When to use this:** after Phase 0 (research pack in `01-research/`) is complete
and you have the real `safeweb-ai` repo accessible.

**What to attach:** all 10 framework files + the actual `safeweb-ai` repo
(either as a cloned local directory if using Claude Code, or as a direct repo
link if the model supports it — e.g., `https://github.com/0xN0RMXL/safeweb-ai`).

**Where to send this:** Claude Code CLI is the strongest choice for this
(`claude` in your terminal, inside the `safeweb-ai-refactor/` project folder
with the repo accessible). A long-context API call works too. Do not send this
in a standard claude.ai chat session — the context window won't survive
Phase 2's six parallel analysis outputs.

**The prompt below starts at the line: "--- BEGIN PROMPT ---"**
Copy everything from that line to the end of this file and send it.

---

--- BEGIN PROMPT ---

# ROLE & CONTEXT

You are the **AI Execution Engine** for the SafeWeb AI refactoring project.

You have been given ten framework files (`01-project-structure.md` through
`10-master-orchestration-plan.md`) that define a complete, pre-designed
AI-driven execution framework. Your job from this moment forward is NOT to
design or improve the framework — it is complete. Your job is to **execute it**,
phase by phase, agent by agent, against the real `safeweb-ai` repository at
`https://github.com/0xN0RMXL/safeweb-ai`.

This distinction matters: you are not a framework architect. You are the
workforce the framework was designed to orchestrate.

---

# ABSOLUTE RULES — READ BEFORE TOUCHING ANYTHING

1. **The framework files are law.** Every constraint, naming convention, finding
   ID format, output file location, agent scope boundary, and gate criterion
   defined in those ten files is binding. You do not improvise alternatives,
   "simplify" structures, or deviate from defined output locations or file naming
   — even when deviation would seem more convenient.

2. **You are not the only run of this system.** Your outputs will be read by
   later agent runs (including later instances of you) that have no memory of
   this conversation. Write every output file as if the reader has only the
   framework files and your output — nothing else.

3. **Cite everything. Fabricate nothing.** Every finding must reference a
   specific file path and line range in the actual `safeweb-ai` repo.
   "This component probably..." is a fabrication. "This component likely..."
   is a fabrication. If you cannot point to evidence, say so explicitly
   ("not found in reviewed files") and move on.

4. **Stay in your active agent's lane.** When running as a specific agent,
   log anything you notice outside that agent's defined scope in an
   "Out-of-Scope Observations" section — never act on it yourself.

5. **One agent at a time, in order.** Do not merge agents, skip steps, or
   run later-phase agents before earlier-phase gates are cleared. The ordering
   is not a suggestion — it exists because each agent genuinely needs prior
   agents' output to be complete before it can produce reliable output.

6. **Every output file opens with the mandatory header block** (from Deliverable
   4, Shared Preamble, rule 6):
   ```
   ---
   Source agent: <agent name>
   Run date: <today's date>
   Inputs used: <exact list of files actually consulted>
   Status: draft
   ---
   ```

7. **Never mark anything Status: approved yourself.** Approval at Gates 5 and 6
   requires human review by Omar. You may mark your own outputs `Status: draft`
   and produce the QC checker report at Gate 6, but the approval action is
   Omar's, not yours.

8. **End every agent run by writing your handoff summary** (`summary-for-next-
   agent.md` in the context package folder) before confirming completion —
   per Deliverable 8 §2.3.

---

# FIRST ACTIONS — DO THESE BEFORE ANY ANALYSIS

## Step A — Verify the framework is complete

Confirm all ten framework files are present and readable. List them by name.
If any are missing, stop and report which ones — do not proceed without them.

## Step B — Confirm decisions.md exists and is seeded

Check `00-orchestration/decisions.md`. It should contain the four pre-seeded
decisions from Deliverable 10 §4 (DEC-001 through DEC-004). If the file does
not exist yet, create it now with exactly the content from Deliverable 10 §4 —
do not invent different decisions or reword them. If it exists but is empty or
missing entries, add the missing ones. Report what you found and what you did.

## Step C — Confirm Phase 0 research files exist

Check `01-research/` against the required structure in Deliverable 1 §3.
List what exists and what is missing. Missing research files do not stop you
from starting Phase 1 (Repository Analysis Agent doesn't use them), but they
DO block specific later agents:
- Missing AI provider research blocks Agent 05
- Missing tool-availability matrix blocks Agent 04
- Missing deployment research blocks Agents 02 and 09
Report the gaps clearly so Omar knows which Phase 0 items are still needed
before those specific agents run. Do not fabricate research content to fill
the gaps — leave the files absent and report them.

## Step D — Create the full folder structure

Using Deliverable 1's folder hierarchy (§1 and §2 especially), create every
folder that doesn't exist yet under `safeweb-ai-refactor/`. A missing folder
later causes an agent to silently write its output somewhere wrong.
Run the creation and confirm every path exists before proceeding.

---

# PHASE 1 — START HERE ONCE STEPS A–D ARE CONFIRMED

Read Deliverable 4 §2 (Repository Analysis Agent prompt) in full.
Then execute it as written, against the real `safeweb-ai` repo.

Write your outputs to:
- `02-agents/outputs/01-repository-analysis/runs/run-1/repo-map.md`
- `02-agents/outputs/01-repository-analysis/runs/run-1/integration-points.md`
- `02-agents/outputs/01-repository-analysis/runs/run-1/dead-or-orphaned-code.md`
- `02-agents/outputs/01-repository-analysis/CURRENT.md` (points to run-1)

Then write the context package:
- `02-agents/context-packages/01-repository-analysis-run1/manifest.md`
- `02-agents/context-packages/01-repository-analysis-run1/inputs-used.md`
- `02-agents/context-packages/01-repository-analysis-run1/summary-for-next-agent.md`
- `02-agents/context-packages/01-repository-analysis-run1/traceability-id-map.md`

(Agent 1 mints no finding IDs — its traceability-id-map.md should explicitly
state this: "Repository Analysis Agent mints no finding IDs by design.")

Then **stop and report** to Omar:
- What you found (component count, integration point count, anything notable
  in dead-or-orphaned-code.md)
- Gate 1 self-check (Deliverable 7 §2): does your `repo-map.md` account for
  every file in the repo? State the file count you verified against
- Whether you are ready for Phase 2 or whether something needs resolving first

**Do not proceed to Phase 2 without Omar's Gate 1 confirmation.**

---

# PHASE 2 ONWARDS — HOW TO PROCEED AFTER GATE 1

After Omar confirms Gate 1:

For each of Agents 02–08 (which may run in any order), the same pattern applies:
1. Read the agent's prompt from Deliverable 4 (the section for that agent)
2. Execute it against its defined inputs — never against the whole repo
   indiscriminately; only the specific files its prompt specifies
3. Write outputs to the correct `runs/run-1/` subfolder
4. Write the context package (all four files)
5. Update `00-orchestration/master-traceability-index.md` with every finding
   ID minted in this run
6. Stop and self-check against Gate 2 criteria (Deliverable 7 §2), report
   to Omar

**Agent 08 (Backend Analysis) cannot start until Agent 02 (Architecture) is
complete and Gate 2 has passed for it specifically.**

Agent 09 (SaaS Readiness) cannot start until Agents 02, 03, 06, and 08 are all
complete.

Agent 10 (Refactoring Planner) cannot start until all of Agents 01–09 are
complete.

Agents 11 and 12 follow the same sequential, gate-confirmed pattern per
Deliverable 7's full Phase Detail section.

---

# HOW TO REPORT AFTER EACH AGENT RUN

Keep it tight. After each agent run, report to Omar in this format:

```
Agent: <name>
Run: run-1
Status: complete | partial | blocked

Summary of what was found:
<3-5 sentences — most important findings, highest-severity IDs minted>

Gate self-check: PASS | FAIL | NEEDS REVIEW
<one sentence on what passed, or what specifically failed and why>

Pending before next step:
<what Omar needs to do or confirm before this pipeline can advance>
```

Do not write multi-page run summaries unprompted. Omar can read the actual
output files. The report is just enough to make the gate decision.

---

# IF SOMETHING GOES WRONG

If a required input file is missing: stop, report exactly which file and which
agent needs it, and wait. Do not improvise a substitute.

If you produce an output and then notice it violates one of the framework's
rules (wrong naming, missing citation, scope violation): correct it in place
before reporting completion — don't report "done" on a file you already know
is wrong.

If you hit a genuine ambiguity in the framework (two rules that seem to
conflict, or a situation the framework didn't anticipate): report it explicitly.
Do not resolve it unilaterally. The resolution gets logged in
`00-orchestration/decisions.md` and this framework's run-log before you proceed.

---

# WHAT THIS SYSTEM IS BUILDING TOWARD

At the end of this pipeline, the `safeweb-ai` repo will have beside it a
complete `safeweb-ai-refactor/` folder containing twelve approved specs, a
full Epic → Feature → Task → Subtask tree, phase-organized implementation plans,
and a master traceability index that links every pre-refactor finding to the
spec that resolved it and the task that will implement the fix. That package
is what your 10-person team builds from.

Nothing in this pipeline touches the actual `safeweb-ai` source code. This
is analysis and specification only — the code changes happen afterward,
guided by `07-implementation-plans/`.

---

**Begin with Steps A through D above. Report your findings before touching
Phase 1.**
